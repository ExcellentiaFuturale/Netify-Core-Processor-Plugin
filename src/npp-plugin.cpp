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

#include <pcap/pcap.h>

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
#include <nd-flow-parser.h>
#include <nd-flow-map.h>
#include <nd-dhc.h>
#include <nd-fhc.h>
class ndInstanceStatus;
#include <nd-plugin.h>
#include <nd-instance.h>

#include "npp-plugin.h"

nppLegacy::nppLegacy(
    const string &tag, const ndPlugin::Params &params)
    : ndPluginProcessor(tag, params)
{
    if (conf_filename.empty())
        throw ndPluginException("conf_filename", strerror(EINVAL));

    reload = true;

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

nppLegacy::~nppLegacy()
{
    int rc;
    if ((rc = pthread_cond_broadcast(&lock_cond)) != 0) {
        throw ndPluginException(
            "pthread_cond_broadcast", strerror(rc)
        );
    }

    Join();

    pthread_cond_destroy(&lock_cond);
    pthread_mutex_destroy(&cond_mutex);

    nd_dprintf("%s: destroyed\n", tag.c_str());
}

void *nppLegacy::Entry(void)
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

    Lock();

    // XXX: Ensure we release any held flow tickets...
    nd_dprintf("%s: clearing %lu flow events...\n", tag.c_str(),
        flow_events.size());

    flow_events.clear();

    Unlock();

    return NULL;
}

void nppLegacy::DispatchEvent(ndPlugin::Event event, void *param)
{
    switch (event) {
    case ndPlugin::EVENT_RELOAD:
        Reload();
        break;
    default:
        break;
    }
}

void nppLegacy::DispatchProcessorEvent(
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

void nppLegacy::DispatchProcessorEvent(
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

void nppLegacy::DispatchProcessorEvent(
    ndPluginProcessor::Event event, ndInterfaces *interfaces)
{
    //nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_INTERFACES:
        break;
    default:
        break;
    }
}

void nppLegacy::DispatchProcessorEvent(
    ndPluginProcessor::Event event,
    const string &iface, ndPacketStats *stats)
{
    //nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_PKT_CAPTURE_STATS:
        break;
    default:
        break;
    }
}

void nppLegacy::DispatchProcessorEvent(
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

void nppLegacy::DispatchProcessorEvent(
    ndPluginProcessor::Event event, ndInstanceStatus *status)
{
    //nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_UPDATE_INIT:
        break;
    default:
        break;
    }
}

void nppLegacy::DispatchProcessorEvent(
    ndPluginProcessor::Event event)
{
    //nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_UPDATE_COMPLETE:
        break;
    default:
        break;
    }
}

void nppLegacy::Reload(void)
{
    nd_dprintf("%s: Loading configuration: %s\n",
        tag.c_str(), conf_filename.c_str()
    );

    json j;
    ifstream ifs(conf_filename);
    if (! ifs.is_open()) {
        nd_printf("%s: Error loading configuration: %s: %s\n",
            tag.c_str(), conf_filename.c_str(), strerror(ENOENT));
        Unlock();
        throw ndPluginException("conf_filename", strerror(ENOENT));
    }

    try {
        ifs >> j;
    }
    catch (exception &e) {
        nd_printf("%s: Error loading configuration: %s: JSON parse error\n",
            tag.c_str(), conf_filename.c_str());
        nd_dprintf("%s: %s: %s\n", tag.c_str(), conf_filename.c_str(), e.what());
        Unlock();
        throw ndPluginException("conf_filename", strerror(EINVAL));
    }

    try {
        sinks_http.clear();
        sinks_socket.clear();
        for (auto &kvp : j["sinks_http"].get<json::object_t>()) {
            if (kvp.second.type() != json::value_t::array) continue;
            sinks_http[kvp.first] = kvp.second.get<ndPlugin::Channels>();
        }
        for (auto &kvp : j["sinks_socket"].get<json::object_t>()) {
            if (kvp.second.type() != json::value_t::array) continue;
            sinks_socket[kvp.first] = kvp.second.get<ndPlugin::Channels>();
        }
    } catch (...) { }
}

void nppLegacy::EncodeFlow(const nppFlowEvent &event)
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

    if (event.event == ndPluginProcessor::EVENT_FLOW_MAP) {
        string flow;
        nd_json_to_string(jflow, flow, ndGC_DEBUG);

        nd_dprintf("%s: %s: %lu bytes\n",
            tag.c_str(), __PRETTY_FUNCTION__, flow.size());

        return;
    }

    for (auto &sink : sinks_http)
        DispatchSinkPayload(sink.first, sink.second, jflow);
    for (auto &sink : sinks_socket)
        DispatchSinkPayload(sink.first, sink.second, jflow);
}

ndPluginInit(nppLegacy);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
