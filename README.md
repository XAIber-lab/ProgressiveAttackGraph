#  A Scalable System for Analysis-driven Attack Graph Generation Through Progressive Data Analysis

## Abstract

In the current networks, where cyber attacks occur daily evolving even more sophisticated, a timely cyber risk assessment becomes paramount.
We focus on the pervasive threat of multi-step attacks, particularly insidious for network security.
Attack Graph (AG) represents the most suited solution to model and analyze these attacks, although they suffer from poor scalability due to the complexity of attack path analysis.

To effectively monitor the exposure to multi-step attacks, we introduces a novel progressive analytics framework for AG generation and attack path analysis.
First, it enables real-time attack path analysis before the completion of the AG generation process with a quantifiable approximation degree. This is achieved by leveraging the concept of statistical significance.
Second, we further enhance the efficiency of attack path analysis by accelerating the AG generation based on specific analysis queries, prioritizing the computation of paths relevant to the analyst's needs. This is achieved through the design of a steering mechanism over the progressive framework.

In this repository, you can find implementation choices, customized configuration files, and validation scenarios.

## Content

The bash files can be used to run the attack graph generation and analysis on Windows (main.bat) and Linux (main.sh) systems.
Python scripts can be found in src\ folder. The main ones are the following:

- sampling.py (implements the sampling and statistics analyses)
- steering.py (implements the steerin mechanism)
- generation.py (implements the generation of the complete attack graph as ground truth)

Additionally, the following scripts have their own main functions to be executed individually, if necessary:

- main.py (implements the main logic of the whole approach StatAG and SteerAG in a multicore enviroment)
- plot_analysis.py (implements the charts for the analysis of StatAG and SteerAG)

## Configuration Parameters

The following parameters can be configured in the config.py file:

- SAMPLING algorithms between BFS, DFS, and Random Walks
- Number of SAMPLES for each iteration (default 100)
- Whether include the steering mechanism or not
- Additional parameters to control the accuracy among the different iterations

In addition, scalability parameters can be configured, such as:

- the number of cores on which run the system
- the number of repeated experiments to perform multiple experiments
- number of hosts, vulnerabilities, topology, and distribution of the synthetic networks to generate
- queries to consider for the analysis

## Prerequisites

The following python packages are required:

- pandas
- networkx
- matplotlib
- sklearn
- numpy
- pebble

## Installation Instructions

0. Unzip the file inventory.zip and put the folder named "inventory" inside src/ folder.

### Using Docker container:

1. Build the docker container in the main folder of the project
2. Inside the container, move inside the "src/" directory
3. Configure the file src/config.py
4. Launch the file main.py

```
python main.py
```

### Without Docker:

1. Configure the file src/config.py
2. Launch the bash file (main.bat for Windows, main.sh for Linux)

```
.\main.bat
```
