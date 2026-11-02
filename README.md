# DNS Log Analysis with Splunk

A beginner learning project exploring how to ingest DNS-related network logs into Splunk Enterprise, understand their fields, and use SPL to summarize and investigate DNS activity.

## Project goals

- Load a public sample log into Splunk.
- Learn how Splunk indexes events and assigns source, host, and source type metadata.
- Inspect raw events and identify the source and destination IP/port fields.
- Practice SPL searches for DNS volume, queried names, response codes, and unusual activity.
- Learn to treat unusual results as investigation leads rather than proof of an attack.

## Dataset

The project uses the sample file [`dns.log.gz`](https://www.secrepo.com/maccdc2012/dns.log.gz) from the Security Repository (SecRepo), associated with MACCDC 2012. Download it from the source and upload it to your own Splunk instance. This repository intentionally does not include the data file.

The events shown during this project have a Zeek/Bro-style, whitespace-separated layout. The beginning of an event resembles:

```text
timestamp uid source_ip source_port destination_ip destination_port protocol transaction_id query ...
```

For example, in an event beginning `... 192.168.202.83 45561 192.168.207.4 53 udp ...`, the likely client/source is `192.168.202.83` and the likely DNS responder/destination is `192.168.207.4`. Other events show different responder IPs, such as `192.168.206.44`; that can be valid in a dataset containing traffic to multiple resolvers. Confirm field order from the original log format before interpreting fields. Events using port 137 are not standard DNS traffic on port 53, even if they are in the same file.

## Ingest in Splunk

1. In Splunk Enterprise, open **Settings → Add Data → Upload**.
2. Select the downloaded `dns.log.gz` file and review the preview.
3. Set a clear source type, for example `dns_logs` (or use the source type already assigned in your Splunk instance).
4. Select the target index and confirm timestamp/event breaking options, then submit.
5. Search for the uploaded data. Replace the example source type/index with the values you chose:

```spl
index=* sourcetype="dns_logs"
| head 10
```

In this learning session, Splunk displayed the source type as `DNS logs` and source as `dns.log.gz`. Source type names are case-sensitive in searches; use the exact value shown by your events.

## Explore events and fields

Start by reviewing raw events and Splunk's automatically available fields:

```spl
source="dns.log.gz" sourcetype="DNS logs"
| head 20
```

Use **Extract New Fields** from the event search page to practice field extraction. Validate against multiple representative rows before saving. Based on the observed layout, the first IP/port pair appears to be the origin/client and the second pair the responder/destination. The sample has different IPs in these positions, so do not assume the DNS server has one address.

If you want to test field positions temporarily with SPL, this pattern is based on the event layout observed in the sample and should be checked against your raw events:

```spl
source="dns.log.gz" sourcetype="DNS logs"
| rex field=_raw "^\\S+\\s+\\S+\\s+(?<src_ip>\\d{1,3}(?:\\.\\d{1,3}){3})\\s+(?<src_port>\\d+)\\s+(?<dst_ip>\\d{1,3}(?:\\.\\d{1,3}){3})\\s+(?<dst_port>\\d+)\\s+(?<protocol>\\S+)"
| table _time src_ip src_port dst_ip dst_port protocol _raw
| head 20
```

The `rex` fields exist only for that search. Save a field extraction in Splunk if you want the fields available to later searches. The exact durable extraction may need adjustment to match the full source format.

## Example SPL searches

### Count events by source and destination

Run after saving `src_ip` and `dst_ip` extractions, or keep the temporary `rex` before `stats`:

```spl
source="dns.log.gz" sourcetype="DNS logs"
| rex field=_raw "^\\S+\\s+\\S+\\s+(?<src_ip>\\d{1,3}(?:\\.\\d{1,3}){3})\\s+(?<src_port>\\d+)\\s+(?<dst_ip>\\d{1,3}(?:\\.\\d{1,3}){3})\\s+(?<dst_port>\\d+)\\s+(?<protocol>\\S+)"
| where dst_port=53
| stats count by src_ip dst_ip
| sort - count
```

### Most active clients

```spl
source="dns.log.gz" sourcetype="DNS logs"
| rex field=_raw "^\\S+\\s+\\S+\\s+(?<src_ip>\\d{1,3}(?:\\.\\d{1,3}){3})"
| stats count by src_ip
| sort - count
| head 20
```

### Query volume over time

```spl
source="dns.log.gz" sourcetype="DNS logs"
| timechart span=5m count
```

### Inspect response codes

If the response code is extracted as `rcode`:

```spl
source="dns.log.gz" sourcetype="DNS logs"
| stats count by rcode
| sort - count
```

### Look at frequent query names

Use the actual query-name field extracted from your data (often named `query` or `fqdn`; verify in Splunk first):

```spl
source="dns.log.gz" sourcetype="DNS logs"
| stats count by query
| sort - count
| head 20
```

### Investigate high query volume per client

```spl
source="dns.log.gz" sourcetype="DNS logs"
| rex field=_raw "^\\S+\\s+\\S+\\s+(?<src_ip>\\d{1,3}(?:\\.\\d{1,3}){3})"
| bin _time span=5m
| stats count by _time src_ip
| sort - count
```

This produces counts to inspect; choose a threshold only after learning the dataset's normal baseline. A spike or an unusual-looking domain is not, by itself, evidence of malicious activity.

## Lessons learned

- A `sourcetype` labels a format; it does not guarantee every row is a DNS request on port 53.
- `stats count by field` requires that field to exist. If it is missing, extract it first or use `rex` in the search.
- `regex _raw="..."` filters events by matching text; it does not extract fields.
- A destination IP can vary between events when traffic uses multiple resolvers or responders.
- Validate field extractions against several raw events, including different query types and port values.
- Interpret response codes and traffic patterns in context; use other evidence before deciding an event is suspicious.

## Limitations

- This is a learning exercise using a public historical sample, not a live production detection system.
- The SPL examples assume the event layout visible in the sample and may need adjustment for other logs or Splunk configurations.
- No threat-intelligence verdicts are included. Domain reputation requires separate, current sources and careful validation.

## Tools

- Splunk Enterprise
- SPL (Search Processing Language)
- SecRepo MACCDC 2012 sample DNS log

## License and data attribution

The sample dataset is hosted by [SecRepo](https://www.secrepo.com/maccdc2012/dns.log.gz). Review the data source's terms and attribution requirements before redistributing any downloaded data. This repository contains analysis notes and SPL examples, not the log file itself.  
