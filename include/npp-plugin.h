// Netify Agent Legacy Processor
// Copyright (C) 2021-2022 eGloo Incorporated <http://www.egloo.ca>

#ifndef _NPP_PLUGIN_H
#define _NPP_PLUGIN_H

class nppFlowEvent
{
public:
    nppFlowEvent(ndPluginProcessor::Event event, nd_flow_ptr& flow)
        : flow(flow), event(event) {
    }

    nd_flow_ptr flow;
    ndPluginProcessor::Event event;
};

class nppLegacy : public ndPluginProcessor
{
public:
    nppLegacy(const string &tag, const ndPlugin::Params &params);
    virtual ~nppLegacy();

    virtual void *Entry(void);

    virtual void GetVersion(string &version) {
        version = PACKAGE_VERSION;
    }
    template <class T>
    void GetStatus(T &output) const {
        nd_dprintf("%s: TODO\n", __PRETTY_FUNCTION__);
        ndPluginProcessor::GetStatus(output);
    }

    virtual void DispatchEvent(
        ndPlugin::Event event, void *param = nullptr);

    virtual void DispatchProcessorEvent(
        ndPluginProcessor::Event event, ndFlowMap *flow_map);
    virtual void DispatchProcessorEvent(
        ndPluginProcessor::Event event, nd_flow_ptr& flow);
    virtual void DispatchProcessorEvent(
        ndPluginProcessor::Event event, ndInterfaces *interfaces);
    virtual void DispatchProcessorEvent(
        ndPluginProcessor::Event event,
        const string &iface, ndPacketStats *stats);
    virtual void DispatchProcessorEvent(
        ndPluginProcessor::Event event, ndPacketStats *stats);
    virtual void DispatchProcessorEvent(
        ndPluginProcessor::Event event, ndInstanceStatus *status);
    virtual void DispatchProcessorEvent(
        ndPluginProcessor::Event event);

protected:
    atomic<bool> reload;

    void Reload(void);

    pthread_cond_t lock_cond;
    pthread_mutex_t cond_mutex;

    map<string, ndPlugin::Channels> sinks_http;
    map<string, ndPlugin::Channels> sinks_socket;

    vector<nppFlowEvent> flow_events;
    vector<nppFlowEvent> flow_events_priv;

    void EncodeFlow(const nppFlowEvent &event);
};

#endif // _NPP_PLUGIN_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
