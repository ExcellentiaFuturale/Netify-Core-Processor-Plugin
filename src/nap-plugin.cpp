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

#include "nap-plugin.h"

napLegacy::napLegacy(
    const string &tag, const ndPlugin::Params &params)
    : ndPluginProcessor(tag, params)
{
    if (conf_filename.empty())
        throw ndPluginException("conf_filename", strerror(EINVAL));

    reload = true;

    nd_dprintf("%s: initialized\n", tag.c_str());
}

napLegacy::~napLegacy()
{
    Join();

    nd_dprintf("%s: destroyed\n", tag.c_str());
}

void *napLegacy::Entry(void)
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

        sleep(1);
    }

    return NULL;
}

void napLegacy::DispatchEvent(ndPlugin::Event event, void *param)
{
    switch (event) {
    case ndPlugin::EVENT_RELOAD:
        Reload();
        break;
    default:
        break;
    }
}

void napLegacy::DispatchProcessorEvent(
    ndPluginProcessor::Event event, ndFlowMap *flow_map)
{
    switch (event) {
    case ndPluginProcessor::EVENT_FLOW_MAP:
        break;
    default:
        break;
    }
}

void napLegacy::DispatchProcessorEvent(
    ndPluginProcessor::Event event, ndFlow *flow)
{
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
        break;
    }
}

void napLegacy::DispatchProcessorEvent(
    ndPluginProcessor::Event event, ndInterfaces *interfaces)
{
    switch (event) {
    case ndPluginProcessor::EVENT_INTERFACES:
        break;
    default:
        break;
    }
}

void napLegacy::DispatchProcessorEvent(
    ndPluginProcessor::Event event,
    const string &iface, ndPacketStats *stats)
{
    switch (event) {
    case ndPluginProcessor::EVENT_PKT_CAPTURE_STATS:
        break;
    default:
        break;
    }
}

void napLegacy::DispatchProcessorEvent(
    ndPluginProcessor::Event event, ndPacketStats *stats)
{
    switch (event) {
    case ndPluginProcessor::EVENT_PKT_GLOBAL_STATS:
        break;
    default:
        break;
    }
}

void napLegacy::DispatchProcessorEvent(
    ndPluginProcessor::Event event, ndInstanceStatus *status)
{
    switch (event) {
    case ndPluginProcessor::EVENT_UPDATE_INIT:
        break;
    default:
        break;
    }
}

void napLegacy::DispatchProcessorEvent(
    ndPluginProcessor::Event event)
{
    switch (event) {
    case ndPluginProcessor::EVENT_UPDATE_COMPLETE:
        break;
    default:
        break;
    }
}

void napLegacy::Reload(void)
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
#if 0
    try {
        log_interval = (time_t)j["log_interval"].get<unsigned>();
    } catch (...) { }

    try {
        nap_privacy_mode = j["privacy_mode"].get<bool>();
    } catch (...) { }

    try {
        sinks.clear();
        for (auto &kvp : j["sinks"].get<json::object_t>()) {
            if (kvp.second.type() != json::value_t::array) continue;
            sinks[kvp.first] = kvp.second.get<ndPlugin::Channels>();
        }
    } catch (...) { }
#endif
}

ndPluginInit(napLegacy);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
