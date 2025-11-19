# Flash

## Introduction

Flash is a network verification system. It monitors data plane configuration and
compares the actual behavior against the expected state.

## Products

- [x] Flash Server for InfiniBand networks
- [] Flash Server for RoCE networks

## Installation

Available on [GHCR
package](https://github.com/CrackedPoly/Rapimt/pkgs/container/flash) and [Docker
Hub](https://hub.docker.com/repository/docker/crackedpolya/flash).

## Usage

`docker run -it flash:latest ib_server -h`

## Plugins

Verification functions, in essence, are functions to compute some properties of
a DAG that represents an packet forwarding EC (We use forwarding graph, DAG and
EC interchangeably). By design, we view verification functions as plugins of two
kind: GraphPlugin and VerifierPlugin.

GraphPlugin requires that the plugin executes on every graph. It is useful in
highly symmetric networks that you are sure that all graphs in your networks
have similar structure.

VerifierPlugin adds only one filed `header space` based on GraphPlugin. Unlike
GraphPlugin, these plugins are not required to execute on every graph. They are
dispatched by the verifier to some ECs based on their header space.

### Available GraphPlugins

🗒️NOTE: Each DAG contains at least one source and one sink.

- SimplePathExactRegexSet: This plugin is defined by a set of path regex and
  expected count. In execution, it finds all simple paths from all sources to
  all sinks. It asserts that the actual matched regex count is equal to the
  expected count. (For example, 'LH:1,LSLH:896' asserts that in a graph, there
  is exactly one path that matches 'LH' and 896 paths that match 'LSLH', 'L'
  stands for Leaf switch, 'S' stands for Spine switch and 'H' stands for Host.)

### Available VerifierPlugins

- 🚧RSL: Requirement Specification Language. Still WIP.

## API

### Runtime RESTful API

The http server is listening on port 3000.

- Get `/api/v1/num_ec`: Get the number of equivalent classes in the network.
- Get `/api/v1/alert`: Get all alerts from all plugins.
- Get `/api/v1/dag/<lid>`: Get the DAG of a specific EC.
- Get `/api/v1/dag/<lid>?source=<guid>`: Get the DAG of a specific EC with a specific source.
