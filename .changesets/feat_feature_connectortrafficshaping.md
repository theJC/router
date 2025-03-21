### Traffic shaping for connectors ([PR #6737](https://github.com/apollographql/router/pull/6737))

Traffic shaping is now supported for connectors. To target a specific source, use the `subgraph_name.source_name` under the new `connector.sources` property of `traffic_shaping`. Settings under `connector.all` will apply to all connectors. `deduplicate_query` is not supported at this time.

Example config:

```
traffic_shaping:
  connector:
    all:
      timeout: 5s
    sources:
      connector-graph.random_person_api:
        global_rate_limit:
          capacity: 20
          interval: 1s
        experimental_http2: http2only
        timeout: 1s
```

By [@andrewmcgivery](https://github.com/andrewmcgivery) in https://github.com/apollographql/router/pull/6737
