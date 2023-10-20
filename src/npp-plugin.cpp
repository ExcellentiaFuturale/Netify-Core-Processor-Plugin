// Netify Agent Core Processor
// Copyright (C) 2021-2023 eGloo Incorporated
// <http://www.egloo.ca>
//
// This program is free software: you can redistribute it
// and/or modify it under the terms of the GNU General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public
// License along with this program.  If not, see
// <http://www.gnu.org/licenses/>.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fstream>
#include <nd-instance.hpp>

#include "npp-plugin.hpp"

void nppChannelConfig::Load(const string &channel, const json &jconf) {
    auto it = jconf.find("types");
    if (it != jconf.end() && it->type() == json::value_t::array)
    {
        vector<string> types = it->get<vector<string>>();
        for (auto &type : types) {
            if (type == "legacy-http") {
                this->types.push_back(
                  nppChannelConfig::TYPE_LEGACY_HTTP);
            }
            else if (type == "legacy-socket") {
                this->types.push_back(
                  nppChannelConfig::TYPE_LEGACY_SOCKET);
            }
            else if (type == "stream-flows") {
                this->types.push_back(
                  nppChannelConfig::TYPE_STREAM_FLOWS);
            }
            else if (type == "stream-stats") {
                this->types.push_back(
                  nppChannelConfig::TYPE_STREAM_STATS);
            }
            else
                throw ndPluginException("types", strerror(EINVAL));
        }
    }

    it = jconf.find("format");
    if (it != jconf.end() && it->type() == json::value_t::string)
    {
        string format = it->get<string>();
        if (format == "json")
            this->format = nppChannelConfig::FORMAT_JSON;
        else if (format == "msgpack")
            this->format = nppChannelConfig::FORMAT_MSGPACK;
        else
            throw ndPluginException("format", strerror(EINVAL));
    }

    it = jconf.find("compressor");
    if (it != jconf.end() && it->type() == json::value_t::string)
    {
        string compressor = it->get<string>();
        if (compressor == "none")
            this->compressor = nppChannelConfig::COMPRESSOR_NONE;
        else if (compressor == "gz")
            this->compressor = nppChannelConfig::COMPRESSOR_GZ;
        else
            throw ndPluginException("compressor", strerror(EINVAL));
    }
}

nppPlugin::nppPlugin(const string &tag, const ndPlugin::Params &params)
  : ndPluginProcessor(tag, params) {
    if (conf_filename.empty())
        throw ndPluginException("conf_filename", strerror(EINVAL));

    reload = true;
    dispatch_update = false;

    int rc;
    pthread_condattr_t cond_attr;

    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    if ((rc = pthread_cond_init(&lock_cond, &cond_attr)) != 0)
        throw ndThreadException(strerror(rc));

    pthread_condattr_destroy(&cond_attr);

    if ((rc = pthread_mutex_init(&cond_mutex, nullptr)) != 0)
        throw ndThreadException(strerror(rc));

    nd_dprintf("%s: initialized\n", tag.c_str());
}

nppPlugin::~nppPlugin() {
    int rc;
    if ((rc = pthread_cond_broadcast(&lock_cond)) != 0) {
        nd_dprintf("%s: pthread_cond_broadcast: %s\n",
          tag.c_str(), strerror(errno));
    }

    Join();

    pthread_cond_destroy(&lock_cond);
    pthread_mutex_destroy(&cond_mutex);

    nd_dprintf("%s: destroyed\n", tag.c_str());
}

void *nppPlugin::Entry(void) {
    int rc;

    nd_printf(
      "%s: %s v%s (C) 2021-2023 eGloo Incorporated.\n",
      tag.c_str(), PACKAGE_NAME, PACKAGE_VERSION);

    for (;;) {
        if (reload.load()) {
            Reload();
            reload = false;
        }

        if (dispatch_update.load()) {
            dispatch_update = false;

            DispatchLegacyPayload();
            DispatchStreamPayload();

            jagent_status.clear();
            jflows.clear();
            jifaces.clear();
            jiface_endpoints.clear();
            jiface_stats.clear();
            jiface_packet_stats.clear();
        }

        Lock();

        if (flow_events.empty()) {
            Unlock();

            if (flow_events_priv.empty() && ShouldTerminate())
                break;

            if ((rc = pthread_mutex_lock(&cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));

            struct timespec ts_cond;
            if (clock_gettime(CLOCK_MONOTONIC, &ts_cond) != 0)
                throw ndThreadException(strerror(errno));

            ts_cond.tv_sec += 1;
            if ((rc = pthread_cond_timedwait(&lock_cond,
                   &cond_mutex, &ts_cond)) != 0 &&
              rc != ETIMEDOUT)
            {
                throw ndThreadException(strerror(rc));
            }

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
            if (! flow_filters.empty()) {
                bool match = false;
                for (auto &expr : flow_filters) {
                    try {
                        if ((match = flow_parser.Parse(
                               flow_events_priv.back().flow, expr)))
                            break;
                    } catch (string &e) {
                        nd_dprintf("%s: %s: %s\n",
                            tag.c_str(), expr.c_str(), e.c_str());
                    }
                }

                if (! match) {
                    flow_events_priv.pop_back();
                    continue;
                }
            }

            json jpayload;
            EncodeFlow(flow_events_priv.back(), jpayload);
            flow_events_priv.pop_back();

            if (jpayload.empty() == false) {
                DispatchPayload(nppChannelConfig::TYPE_LEGACY_SOCKET,
                  jpayload);
                DispatchPayload(nppChannelConfig::TYPE_STREAM_FLOWS,
                  jpayload);
            }
        }
    }

    return nullptr;
}

void nppPlugin::DispatchEvent(ndPlugin::Event event, void *param) {
    switch (event) {
    case ndPlugin::EVENT_RELOAD: reload = true; break;
    default: break;
    }
}

void nppPlugin::DispatchProcessorEvent(
  ndPluginProcessor::Event event, ndFlowMap *flow_map) {
    switch (event) {
    case ndPluginProcessor::EVENT_FLOW_MAP: break;
    default: return;
    }

    Lock();

    size_t buckets = flow_map->GetBuckets();

    for (size_t b = 0; b < buckets; b++) {
        auto &fm = flow_map->Acquire(b);

        for (auto &it : fm) {
            if (! it.second->flags.detection_init.load())
                continue;
            if (it.second->flags.expired.load()) continue;
            if (it.second->stats.lower_packets.load() == 0 &&
              it.second->stats.upper_packets.load() == 0)
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
              "pthread_cond_broadcast", strerror(rc));
        }
    }
}

void nppPlugin::DispatchProcessorEvent(
  ndPluginProcessor::Event event, nd_flow_ptr &flow) {
#if 0
    nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);
#endif
    switch (event) {
    case ndPluginProcessor::EVENT_FLOW_NEW:
    case ndPluginProcessor::EVENT_FLOW_UPDATED:
    case ndPluginProcessor::EVENT_FLOW_EXPIRED: break;
    default: return;
    }

    Lock();

    flow_events.push_back(nppFlowEvent(event, flow));

    Unlock();

    int rc;
    if ((rc = pthread_cond_broadcast(&lock_cond)) != 0) {
        throw ndPluginException("pthread_cond_broadcast",
          strerror(rc));
    }
}

void nppPlugin::DispatchProcessorEvent(
  ndPluginProcessor::Event event, ndInterfaces *interfaces) {
    // nd_dprintf("%s: %s\n", tag.c_str(),
    // __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_INTERFACES:
        EncodeInterfaces(interfaces);
        break;
    default: break;
    }
}

void nppPlugin::DispatchProcessorEvent(ndPluginProcessor::Event event,
  const string &iface, ndPacketStats *stats) {
    // nd_dprintf("%s: %s\n", tag.c_str(),
    // __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_PKT_CAPTURE_STATS:
        EncodeInterfaceStats(iface, stats);
        break;
    default: break;
    }
}

void nppPlugin::DispatchProcessorEvent(
  ndPluginProcessor::Event event, ndPacketStats *stats) {
    // nd_dprintf("%s: %s\n", tag.c_str(),
    // __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_PKT_GLOBAL_STATS:
        EncodeGlobalPacketStats(stats);
        break;
    default: break;
    }
}

void nppPlugin::DispatchProcessorEvent(
  ndPluginProcessor::Event event, ndInstanceStatus *status) {
    // nd_dprintf("%s: %s\n", tag.c_str(),
    // __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_UPDATE_INIT:
        EncodeAgentStatus(status);
        break;
    default: break;
    }
}

void nppPlugin::DispatchProcessorEvent(ndPluginProcessor::Event event) {
    // nd_dprintf("%s: %s\n", tag.c_str(),
    // __PRETTY_FUNCTION__);
    switch (event) {
    case ndPluginProcessor::EVENT_UPDATE_COMPLETE:
        dispatch_update = true;
        break;
    default: break;
    }
}

void nppPlugin::Reload(void) {
    nd_dprintf("%s: Loading configuration: %s\n",
      tag.c_str(), conf_filename.c_str());

    json j;
    ifstream ifs(conf_filename);
    if (! ifs.is_open()) {
        nd_printf(
          "%s: Error loading configuration: %s: %s\n",
          tag.c_str(), conf_filename.c_str(), strerror(ENOENT));
        throw ndPluginException("conf_filename", strerror(ENOENT));
    }

    try {
        ifs >> j;
    }
    catch (exception &e) {
        nd_printf(
          "%s: Error loading configuration: %s: JSON parse "
          "error\n",
          tag.c_str(), conf_filename.c_str());
        nd_dprintf("%s: %s: %s\n", tag.c_str(),
          conf_filename.c_str(), e.what());
        throw ndPluginException("conf_filename", strerror(EINVAL));
    }

    defaults.Load("defaults", j);

    Lock();

    sinks.clear();

    try {
        auto jflow_filters = j.find("flow_filters");
        if (jflow_filters != j.end() &&
          jflow_filters->type() == json::value_t::array)
        {
            flow_filters = jflow_filters->get<FlowFilters>();
        }

        auto jsinks = j.find("sinks");

        if (jsinks != j.end()) {
            for (auto &jsink : jsinks->get<json::object_t>())
            {
                for (auto &jchannel :
                  jsink.second.get<json::object_t>())
                {
                    auto it = jchannel.second.find(
                      "enable");
                    if (it != jchannel.second.end() &&
                      it->type() == json::value_t::boolean &&
                      it->get<bool>() != true)
                        continue;

                    nppChannelConfig config;

                    config.Load(jchannel.first,
                      jchannel.second, defaults);

                    auto sink = sinks.find(jsink.first);
                    if (sink == sinks.end()) {
                        map<string, nppChannelConfig> entry;

                        entry.insert(
                          make_pair(jchannel.first, config));
                        sinks.insert(make_pair(jsink.first, entry));
                    }
                    else {
                        sink->second.insert(
                          make_pair(jchannel.first, config));
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

void nppPlugin::DispatchPayload(
  nppChannelConfig::Type chan_type, const json &jpayload) {
    for (auto &sink : sinks) {
        for (auto &channel : sink.second) {
            if (find(channel.second.types.begin(),
                  channel.second.types.end(),
                  chan_type) == channel.second.types.end())
                continue;

            uint8_t flags =
              (chan_type == nppChannelConfig::TYPE_LEGACY_SOCKET) ?
              ndPlugin::DF_ADD_HEADER :
              ndPlugin::DF_NONE;

            switch (channel.second.format) {
            case nppChannelConfig::FORMAT_JSON:
                flags |= ndPlugin::DF_FORMAT_JSON;
                break;
            case nppChannelConfig::FORMAT_MSGPACK:
                flags |= ndPlugin::DF_FORMAT_MSGPACK;
                break;
            default: break;
            }

            switch (channel.second.compressor) {
            case nppChannelConfig::COMPRESSOR_GZ:
                flags |= ndPlugin::DF_GZ_DEFLATE;
                break;
            default: break;
            }

            DispatchSinkPayload(sink.first,
              { channel.first }, jpayload, flags);
        }
    }
}

void nppPlugin::EncodeFlow(const nppFlowEvent &event, json &jpayload) {
    json jflow;
    uint8_t encode_options = ndFlow::ENCODE_METADATA;

    switch (event.event) {
    case ndPluginProcessor::EVENT_FLOW_MAP:
        encode_options |= ndFlow::ENCODE_STATS;
        encode_options |= ndFlow::ENCODE_TUNNELS;
        break;
    case ndPluginProcessor::EVENT_FLOW_NEW:
    case ndPluginProcessor::EVENT_FLOW_UPDATED:
        encode_options |= ndFlow::ENCODE_TUNNELS;
        break;
    case ndPluginProcessor::EVENT_FLOW_EXPIRED:
        encode_options = ndFlow::ENCODE_STATS;
        break;
    default: return;
    }

    event.flow->Encode(jflow, event.stats, encode_options);

    if (event.event == ndPluginProcessor::EVENT_FLOW_MAP) {
        auto it = jflows.find(event.flow->iface->ifname);
        if (it != jflows.end()) it->second.push_back(jflow);
        else {
            vector<json> jf = { jflow };
            jflows.insert(make_pair(event.flow->iface->ifname, jf));
        }
    }

    switch (event.event) {
    case ndPluginProcessor::EVENT_FLOW_NEW:
    case ndPluginProcessor::EVENT_FLOW_UPDATED:
        jpayload["type"] = "flow";
        break;
    case ndPluginProcessor::EVENT_FLOW_MAP:
        jpayload["type"] = "flow_stats";
        jflow.clear();
        event.flow->Encode(jflow, event.stats, ndFlow::ENCODE_STATS);
        break;
    case ndPluginProcessor::EVENT_FLOW_EXPIRED:
        jpayload["type"] = "flow_purge";
        jpayload["reason"] =
          (event.flow->ip_protocol == IPPROTO_TCP &&
            event.flow->flags.tcp_fin_ack.load()) ?
          "closed" :
          "expired";
        break;
    default: return;
    }

    jpayload["interface"] = event.flow->iface->ifname;
    jpayload["internal"] = (event.flow->iface->role == ndIR_LAN);
    // XXX: Deprecated
    // jpayload["established"] = false;
    jpayload["flow"] = jflow;
}

void nppPlugin::EncodeAgentStatus(ndInstanceStatus *status) {
    status->Encode(jagent_status);
}

void nppPlugin::EncodeInterfaces(ndInterfaces *interfaces) {
    static const vector<string> keys = { "addr" };

    for (auto &i : *interfaces) {
        json jo;
        i.second->Encode(jo);
        i.second->EncodeAddrs(jo, keys);

        jifaces[i.second->ifname] = jo;

        i.second->EncodeEndpoints(
          i.second->LastEndpointSnapshot(), jiface_endpoints);
    }
}

void nppPlugin::EncodeInterfaceStats(const string &iface,
  ndPacketStats *stats) {
    json jo;
    stats->Encode(jo);

    jiface_stats[iface] = jo;
}

void nppPlugin::EncodeGlobalPacketStats(ndPacketStats *stats) {
    json jo;
    stats->Encode(jo);

    jiface_packet_stats = jo;
}

void nppPlugin::DispatchLegacyPayload(void) {
    json jpayload(jagent_status);
    jpayload["version"] = _NPP_LEGACY_JSON_VERSION;
    jpayload["flows"] = jflows;
    jpayload["interfaces"] = jifaces;
    jpayload["devices"] = jiface_endpoints;
    jpayload["stats"] = jiface_stats;

    DispatchPayload(nppChannelConfig::TYPE_LEGACY_HTTP, jpayload);

    jpayload.clear();
    jpayload["type"] = "agent_hello";
    jpayload["agent_version"] = nd_get_version();
    jpayload["build_version"] = nd_get_version_and_features();
    jpayload["json_version"] = _NPP_LEGACY_JSON_VERSION;

    DispatchPayload(nppChannelConfig::TYPE_LEGACY_SOCKET, jpayload);

    jpayload.clear();
    jpayload = jagent_status;
    jpayload["type"] = "agent_status";

    DispatchPayload(nppChannelConfig::TYPE_LEGACY_SOCKET, jpayload);
}

void nppPlugin::DispatchStreamPayload(void) {
    json jpayload(jagent_status);

    jpayload["type"] = "agent_status";

    DispatchPayload(nppChannelConfig::TYPE_STREAM_STATS, jpayload);

    jpayload.clear();
    jpayload = jifaces;
    jpayload["type"] = "interfaces";

    DispatchPayload(nppChannelConfig::TYPE_STREAM_STATS, jpayload);

    jpayload.clear();
    jpayload = jiface_endpoints;
    jpayload["type"] = "endpoints";

    DispatchPayload(nppChannelConfig::TYPE_STREAM_STATS, jpayload);

    jpayload.clear();
    jpayload = jiface_stats;
    jpayload["type"] = "interface_stats";

    DispatchPayload(nppChannelConfig::TYPE_STREAM_STATS, jpayload);

    jpayload.clear();
    jpayload = jiface_packet_stats;
    jpayload["type"] = "global_stats";

    DispatchPayload(nppChannelConfig::TYPE_STREAM_STATS, jpayload);
}

ndPluginInit(nppPlugin);
