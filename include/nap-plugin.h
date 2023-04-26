// Netify Agent Legacy Processor
// Copyright (C) 2021-2022 eGloo Incorporated <http://www.egloo.ca>

#ifndef _NAP_PLUGIN_H
#define _NAP_PLUGIN_H

class napLegacy : public ndPluginProcessor
{
public:
    napLegacy(const string &tag, const ndPlugin::Params &params);
    virtual ~napLegacy();

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
        ndPluginProcessor::Event event, ndFlow *flow);
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
};

#endif // _NAP_PLUGIN_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
