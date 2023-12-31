// Netify Agent Core Processor
// Copyright (C) 2021-2023 eGloo Incorporated
// <http://www.egloo.ca>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _NPP_PLUGIN_H
#define _NPP_PLUGIN_H

#include <nd-flow-parser.hpp>
#include <nd-plugin.hpp>

#define _NPP_LEGACY_JSON_VERSION 1.9

class nppChannelConfig
{
public:
    enum Type {
        TYPE_INVALID,
        TYPE_LEGACY_HTTP,
        TYPE_LEGACY_SOCKET,
        TYPE_STREAM_FLOWS,
        TYPE_STREAM_STATS,
    };

    enum Format {
        FORMAT_RAW,
        FORMAT_JSON,
        FORMAT_MSGPACK,
    };

    enum Compressor {
        COMPRESSOR_NONE,
        COMPRESSOR_GZ,
    };

    nppChannelConfig()
      : format(FORMAT_JSON), compressor(COMPRESSOR_NONE) { }

    void Load(const string &channel, const json &jconf);
    inline void Load(const string &channel,
      const json &jconf, nppChannelConfig &defaults) {
        types = defaults.types;
        format = defaults.format;
        compressor = defaults.compressor;
        Load(channel, jconf);
    }

    string channel;
    vector<Type> types;
    Format format;
    Compressor compressor;
};

class nppFlowEvent
{
public:
    nppFlowEvent(ndPluginProcessor::Event event, nd_flow_ptr &flow)
      : flow(flow), event(event), stats(flow->stats) { }

    nd_flow_ptr flow;
    ndPluginProcessor::Event event;
    ndFlowStats stats;
};

class nppPlugin : public ndPluginProcessor
{
public:
    nppPlugin(const string &tag, const ndPlugin::Params &params);
    virtual ~nppPlugin();

    virtual void *Entry(void);

    virtual void GetVersion(string &version) {
        version = PACKAGE_VERSION;
    }
    template <class T>
    void GetStatus(T &output) const {
        nd_dprintf("%s: TODO\n", __PRETTY_FUNCTION__);
        ndPluginProcessor::GetStatus(output);
    }

    virtual void DispatchEvent(ndPlugin::Event event,
      void *param = nullptr);

    virtual void DispatchProcessorEvent(
      ndPluginProcessor::Event event, ndFlowMap *flow_map);
    virtual void DispatchProcessorEvent(
      ndPluginProcessor::Event event, nd_flow_ptr &flow);
    virtual void DispatchProcessorEvent(
      ndPluginProcessor::Event event, ndInterfaces *interfaces);
    virtual void DispatchProcessorEvent(ndPluginProcessor::Event event,
      const string &iface, ndPacketStats *stats);
    virtual void DispatchProcessorEvent(
      ndPluginProcessor::Event event, ndPacketStats *stats);
    virtual void DispatchProcessorEvent(
      ndPluginProcessor::Event event, ndInstanceStatus *status);
    virtual void
    DispatchProcessorEvent(ndPluginProcessor::Event event);

protected:
    atomic<bool> reload;
    atomic<bool> dispatch_update;

    void Reload(void);

    pthread_cond_t lock_cond;
    pthread_mutex_t cond_mutex;

    nppChannelConfig defaults;
    map<string, map<string, nppChannelConfig>> sinks;

    vector<nppFlowEvent> flow_events;
    vector<nppFlowEvent> flow_events_priv;

    ndFlowParser flow_parser;
    typedef vector<string> FlowFilters;
    FlowFilters flow_filters;

    virtual void DispatchPayload(
      nppChannelConfig::Type chan_type, const json &jpayload);

    void EncodeFlow(const nppFlowEvent &event, json &jpayload);

    json jagent_status;
    map<string, vector<json>> jflows;
    json jifaces;
    json jiface_endpoints;
    json jiface_stats;
    json jiface_packet_stats;

    void EncodeAgentStatus(ndInstanceStatus *status);
    void EncodeInterfaces(ndInterfaces *interfaces);
    void EncodeInterfaceStats(const string &iface,
      ndPacketStats *stats);
    void EncodeGlobalPacketStats(ndPacketStats *stats);

    void DispatchLegacyPayload(void);
    void DispatchStreamPayload(void);
};

#endif  // _NPP_PLUGIN_H
