# Netify Agent Core Processor Plugin
Copyright &copy; 2022 eGloo Incorporated

[![pipeline status](https://gitlab.com/netify.ai/private/netify-plugins/netify-proc-core/badges/master/pipeline.svg)](https://gitlab.com/netify.ai/private/netify-plugins/netify-proc-core/-/commits/master)

## Overview

The aggregator plugin produces aggregated JSON summaries of protocol and application statistics over a configurable interval of time.

A new log file will be created after the configured interval of time has expired.  The generated log files will not be deleted.  It is up to the integrator to implement post-processing clean-up (deleting) of the log files.  The log files are JSON encoded.

## Configuration

The default configuration path is: `/etc/netifyd/netify-proc-core.json`

When the configuration file is updated, it can be re-loaded without restarting by sending a `SIGHUP` to the Netify Agent.  The plugin configuration file will also be reloaded.

### Configuration Directives

- `privacy_mode`  
    Set to `true` to omit MAC and IP addresses.
- `log_interval`  
    Set to the desired aggregate interval (in seconds).  Log files will be generated every `log_interval` seconds.
- `log_path`  
    The directory where log files will be created.
- `log_prefix`  
    The filename prefix used when creating a new log file.
- `log_suffix`  
    The filename suffix (including an optional extension such as `.log` or `.json`), used when creating a new log file.
- `overwrite`  
    When enabled, filenames do not include a timestamp and will be overwritten by each update.

## Example Configuration

The following example configuration instructs the plugin to output flow stats every minute.  The stats entries will be grouped by device (MAC address), and then by IP address (privacy mode is disabled).

```
{
    "privacy_mode": false,
    "log_path": "/tmp",
    "log_prefix": "netify-proc-core-",
    "log_suffix": ".json",
    "log_interval": 60,
    "overwrite": false,
}
```

## JSON Log Structure

The top-level keys are:
- `log_time_start`  
    The Unix Epoch time of the log (seconds).
- `log_time_end`  
    The Unix Epoch time of the log end (seconds).
- `stats`  
    An array of log entries which contain the aggregate statistics for the log period (interval).  If the plugin is configured without privacy mode enabled, then the first two top-level keys will include the device MAC address first followed by the IP address.  The subsequent statistics are aggregated by application and then by protocol.

### Example JSON Log Entry

The following is an example `stats` array log entry using a configuration file where `privacy_mode` has been disabled:
```
    "00:90:fb:26:27:68": {
      "67.204.229.236": {
        "140.netify.apple": {
          "196": {
            "download": 283,
            "packets": 8,
            "upload": 295
          }
        }
      }
    },
```
