// Netify Agent Legacy Processor
// Copyright (C) 2021-2022 eGloo Incorporated <http://www.egloo.ca>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdexcept>
#include <vector>
#include <set>
#include <list>
#include <map>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <fstream>
#include <sstream>
#include <atomic>
#include <regex>
#include <iomanip>
#include <mutex>

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

#include <netifyd.h>
#include <nd-config.h>
#include <nd-signal.h>
#include <nd-ndpi.h>
#include <nd-risks.h>
#include <nd-serializer.h>
#include <nd-packet.h>
#include <nd-json.h>
#include <nd-util.h>
#include <nd-addr.h>
#include <nd-thread.h>
#include <nd-netlink.h>
#include <nd-apps.h>
#include <nd-protos.h>
#include <nd-category.h>
#include <nd-flow.h>
#include <nd-flow-map.h>
#include <nd-dhc.h>
#include <nd-fhc.h>
class ndInstanceStatus;
#include <nd-plugin.h>
#include <nd-instance.h>
#include <nd-flow-parser.h>

#include "npp-plugin.h"

void nppChannelConfig::Load(
    const string &channel, const json &jconf)
{
    auto it = jconf.find("type");
    if (it != jconf.end() && it->type() == json::value_t::string) {
        string type = it->get<string>();
        if (type == "legacy-http")
            this->type = nppChannelConfig::TYPE_LEGACY_HTTP;
        else if (type == "legacy-socket")
            this->type = nppChannelConfig::TYPE_LEGACY_SOCKET;
        else
            throw ndPluginException("type", strerror(EINVAL));
    }

    it = jconf.find("format");
    if (it != jconf.end() && it->type() == json::value_t::string) {
        string format = it->get<string>();
        if (format == "json")
            this->format = nppChannelConfig::FORMAT_JSON;
        else if (format == "msgpack")
            this->format = nppChannelConfig::FORMAT_MSGPACK;
        else
            throw ndPluginException("format", strerror(EINVAL));
    }

    it = jconf.find("compressor");
    if (it != jconf.end() && it->type() == json::value_t::string) {
        string compressor = it->get<string>();
        if (compressor == "none")
            this->compressor = nppChannelConfig::COMPRESSOR_NONE;
        else if (compressor == "gz")
            this->compressor = nppChannelConfig::COMPRESSOR_GZ;
        else
            throw ndPluginException("compressor", strerror(EINVAL));
    }
}

nppPlugin::nppPlugin(
    const string &tag, const ndPlugin::Params &params)
    : ndPluginProcessor(tag, params)
{
    if (conf_filename.empty())
        throw ndPluginException("conf_filename", strerror(EINVAL));

    reload = true;
    http_post = false;

    int rc;
    pthread_condattr_t cond_attr;

    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    if ((rc = pthread_cond_init(&lock_cond, &cond_attr)) != 0)
        throw ndThreadException(strerror(rc));

    pthread_condattr_destroy(&cond_attr);

    if ((rc = pthread_mutex_init(&cond_mutex, NULL)) != 0)
        throw ndThreadException(strerror(rc));

    nd_dprintf("%s: initialized\n", tag.c_str());
}

nppPlugin::~nppPlugin()
{
    int rc;
    if ((rc = pthread_cond_broadcast(&lock_cond)) != 0) {
        nd_dprintf("%s: pthread_cond_broadcast: %s\n",
            tag.c_str(), strerror(errno)
        );
    }

    Join();

    pthread_cond_destroy(&lock_cond);
    pthread_mutex_destroy(&cond_mutex);

    nd_dprintf("%s: destroyed\n", tag.c_str());
}

void *nppPlugin::Entry(void)
{
    int rc;

    nd_printf(
        "%s: %s v%s (C) 2021-2023 eGloo Incorporated.\n",
        tag.c_str(), PACKAGE_NAME, PACKAGE_VERSION
    );

    while (! ShouldTerminate()) {

        if (reload.load()) {
            Reload();
            reload = false;
        }

        if (http_post.load()) {
            DispatchPostPayload();
            http_post = false;
        }

        Lock();

        if (flow_events.empty()) {
            Unlock();

            if ((rc = pthread_mutex_lock(&cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));
            if ((rc = pthread_cond_wait(&lock_cond, &cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));
            if ((rc = pthread_mutex_unlock(&cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));

            continue;
        }

        while (! flow_events.empty()) {
            flow_events_priv.push_back(flow_events.back());
            flow_events.pop_back();
        }

        Unlock();

        while (! flow_events_priv.empty()) {
            EncodeFlow(flow_events_priv.back());
            flow_events_priv.pop_back();
        }
    }

    return NULL;
}

void nppPlugin::DispatchEvent(ndPlugin::Event event, void *param)
{
    switch (event) {
    case ndPlugin::EVENT_RELOAD:
        Reload();
        break;
    default:
        break;
    }
}

void nppPlugin::DispatchProcessorEvent(
    ndPluginProcessor::Event event, ndFlowMap *flow_map)
{
    switch (event) {
    case ndPluginProcessor::EVENT_FLOW_MAP:
        break;
    default:
        return;
    }

    Lock();

    size_t buckets = flow_map->GetBuckets();

    for (size_t b = 0; b < buckets; b++) {
        auto &fm = flow_map->Acquire(b);

        for (auto &it : fm) {
            if (! it.second->flags.detection_complete.load())
                continue;
            if (it.second->flags.expired.load() ||
                it.second->flags.expiring.load())
                continue;

            flow_events.push_back(nppFlowEvent(event, it.second));
        }

        flow_map->Release(b);
    }

    bool broadcast = (! flow_events.empty());

    Unlock();

    if (broadcast) {
        int rc;
        if ((rc = pthread_cond_broadcast(&lock_cond)) != 0) {
            throw ndPluginException(
                "pthread_cond_broadcast", strerror(rc)
            );
        }
    }
}

void nppPlugin::DispatchProcessorEvent(
    ndPluginProcessor::Event event, nd_flow_ptr& flow)
{
#if 0
    nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_FLOW_NEW:
        break;
    case ndPluginProcessor::EVENT_FLOW_UPDATED:
        break;
    case ndPluginProcessor::EVENT_FLOW_EXPIRING:
        break;
    case ndPluginProcessor::EVENT_FLOW_EXPIRED:
        break;
    default:
        return;
    }
#endif
    Lock();

    flow_events.push_back(nppFlowEvent(event, flow));

    Unlock();

    int rc;
    if ((rc = pthread_cond_broadcast(&lock_cond)) != 0) {
        throw ndPluginException(
            "pthread_cond_broadcast", strerror(rc)
        );
    }
}

void nppPlugin::DispatchProcessorEvent(
    ndPluginProcessor::Event event, ndInterfaces *interfaces)
{
    //nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_INTERFACES:
        EncodeInterfaces(interfaces);
        break;
    default:
        break;
    }
}

void nppPlugin::DispatchProcessorEvent(
    ndPluginProcessor::Event event,
    const string &iface, ndPacketStats *stats)
{
    //nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_PKT_CAPTURE_STATS:
        EncodeInterfaceStats(iface, stats);
        break;
    default:
        break;
    }
}

void nppPlugin::DispatchProcessorEvent(
    ndPluginProcessor::Event event, ndPacketStats *stats)
{
    //nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_PKT_GLOBAL_STATS:
        break;
    default:
        break;
    }
}

void nppPlugin::DispatchProcessorEvent(
    ndPluginProcessor::Event event, ndInstanceStatus *status)
{
    //nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_UPDATE_INIT:
        EncodeAgentStatus(status);
        break;
    default:
        break;
    }
}

void nppPlugin::DispatchProcessorEvent(
    ndPluginProcessor::Event event)
{
    //nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_UPDATE_COMPLETE:
        http_post = true;
        break;
    default:
        break;
    }
}

void nppPlugin::Reload(void)
{
    nd_dprintf("%s: Loading configuration: %s\n",
        tag.c_str(), conf_filename.c_str()
    );

    json j;
    ifstream ifs(conf_filename);
    if (! ifs.is_open()) {
        nd_printf("%s: Error loading configuration: %s: %s\n",
            tag.c_str(), conf_filename.c_str(), strerror(ENOENT));
        throw ndPluginException("conf_filename", strerror(ENOENT));
    }

    try {
        ifs >> j;
    }
    catch (exception &e) {
        nd_printf("%s: Error loading configuration: %s: JSON parse error\n",
            tag.c_str(), conf_filename.c_str());
        nd_dprintf("%s: %s: %s\n", tag.c_str(), conf_filename.c_str(), e.what());
        throw ndPluginException("conf_filename", strerror(EINVAL));
    }

    defaults.Load("defaults", j);

    Lock();

    sinks.clear();

    try {
        auto jsinks = j.find("sinks");

        if (jsinks != j.end()) {

            for (auto &jsink : jsinks->get<json::object_t>()) {

                for (auto &jchannel :
                    jsink.second.get<json::object_t>()) {

                    auto it = jchannel.second.find("enable");
                    if (it != jchannel.second.end() &&
                        it->type() == json::value_t::boolean &&
                        it->get<bool>() != true) continue;

                    nppChannelConfig config;

                    config.Load(
                        jchannel.first, jchannel.second, defaults
                    );

                    auto sink = sinks.find(jsink.first);
                    if (sink == sinks.end()) {
                        map<string, nppChannelConfig> entry;

                        entry.insert(
                            make_pair(jchannel.first, config)
                        );
                        sinks.insert(
                            make_pair(jsink.first, entry)
                        );
                    }
                    else {
                        sink->second.insert(
                            make_pair(jchannel.first, config)
                        );
                    }
                }
            }
        }
    }
    catch (exception &e) {
        Unlock();
        throw e;
    }

    Unlock();
}

void nppPlugin::DispatchSinkPayload(
    nppChannelConfig::Type type, const json &jpayload)
{
    for (auto &sink : sinks) {

        for (auto &channel : sink.second) {

            if (channel.second.type != type) continue;

            uint8_t flags = (
                type == nppChannelConfig::TYPE_LEGACY_SOCKET
                ) ? ndPlugin::DF_ADD_HEADER : ndPlugin::DF_NONE;

            switch (channel.second.format) {
            case nppChannelConfig::FORMAT_JSON:
                flags |= ndPlugin::DF_FORMAT_JSON;
                break;
            case nppChannelConfig::FORMAT_MSGPACK:
                flags |= ndPlugin::DF_FORMAT_MSGPACK;
                break;
            default:
                break;
            }

            switch (channel.second.compressor) {
            case nppChannelConfig::COMPRESSOR_GZ:
                flags |= ndPlugin::DF_GZ_DEFLATE;
                break;
            default:
                break;
            }

            ndPluginProcessor::DispatchSinkPayload(
                sink.first, { channel.first }, jpayload, flags
            );
        }
    }
}

void nppPlugin::EncodeFlow(const nppFlowEvent &event)
{
    json jflow;

    uint8_t encode_options = ndFlow::ENCODE_NONE;

    switch (event.event) {
    case ndPluginProcessor::EVENT_FLOW_MAP:
    case ndPluginProcessor::EVENT_FLOW_NEW:
        encode_options = ndFlow::ENCODE_ALL;
        break;
    case ndPluginProcessor::EVENT_FLOW_UPDATED:
        encode_options = (
            ndFlow::ENCODE_METADATA | ndFlow::ENCODE_STATS
        );
        break;
    case ndPluginProcessor::EVENT_FLOW_EXPIRING:
        break;
    case ndPluginProcessor::EVENT_FLOW_EXPIRED:
        encode_options = ndFlow::ENCODE_STATS;
        break;
    }

    if (encode_options == ndFlow::ENCODE_NONE)
        return;

    event.flow->Encode(jflow, encode_options);

    if ((encode_options & ndFlow::ENCODE_STATS)) {
        jflow["lower_packets"] = event.stats.lower_packets.load();
        jflow["upper_packets"] = event.stats.upper_packets.load();
        jflow["total_packets"] = event.stats.total_packets.load();
        jflow["lower_bytes"] = event.stats.lower_bytes.load();
        jflow["upper_bytes"] = event.stats.upper_bytes.load();
        jflow["total_bytes"] = event.stats.total_bytes.load();
        jflow["detection_packets"] = event.stats.detection_packets.load();
    }

    if (event.event == ndPluginProcessor::EVENT_FLOW_MAP) {
        auto it = jpost_flows.find(event.flow->iface.ifname);
        if (it != jpost_flows.end())
            it->second.push_back(jflow);
        else {
            vector<json> jf = { jflow };
            jpost_flows.insert(
                make_pair(
                    event.flow->iface.ifname, jf
                )
            );
        }

        return;
    }

    DispatchSinkPayload(
        nppChannelConfig::TYPE_LEGACY_SOCKET, jflow
    );
}

void nppPlugin::EncodeAgentStatus(ndInstanceStatus *status)
{
    jpost.clear();
    jpost["version"] = _NPP_LEGACY_JSON_VERSION;

    status->Encode(jpost);
}

void nppPlugin::EncodeInterfaces(ndInterfaces *interfaces)
{
    static const vector<string> keys = { "addr" };

    for (auto &i : *interfaces) {
        json jo;
        i.second.Encode(jo);
        i.second.EncodeAddrs(jo, keys);

        jpost_ifaces[i.second.ifname] = jo;

        i.second.EncodeEndpoints(
            i.second.LastEndpointSnapshot(), jpost_iface_endpoints
        );
    }
}

void nppPlugin::EncodeInterfaceStats(
    const string &iface, ndPacketStats *stats)
{
    json jo;
    stats->Encode(jo);

    jpost_iface_stats[iface] = jo;
}

void nppPlugin::DispatchPostPayload(void)
{
    jpost["flows"] = jpost_flows;
    jpost_flows.clear();

    jpost["interfaces"] = jpost_ifaces;
    jpost_ifaces.clear();

    jpost["devices"] = jpost_iface_endpoints;
    jpost_iface_endpoints.clear();

    jpost["stats"] = jpost_iface_stats;
    jpost_iface_stats.clear();

    DispatchSinkPayload(
        nppChannelConfig::TYPE_LEGACY_HTTP, jpost
    );

    jpost.clear();
}

ndPluginInit(nppPlugin);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
