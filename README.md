<p align="left">
  <img src="./resources/mito_icon.png" width="280">
</p>
<!--
##### MITO (Multi-attack Impact-aware Transient Optimizer for Firewall Reconfiguration) is a framework designed to compute an optimized order for enforcing distributed firewall reconfiguration changes. MITO prioritizes the updates that mitigate the most impactful attacks during the reconfiguration transient, using constraint programming and a partial weighted Maximum Satisfiability Modulo Theories (MaxSMT) formulation.
-->

## MITO Architecture

### High Level Overview
MITO (Multi-attack Impact-aware Transient Optimizer for Firewall Reconfiguration) is a framework designed to optimize the enforcement order of distributed firewall reconfiguration changes.

When a distributed firewall is reconfigured, the required updates are usually applied one after another. During this transient phase, some attacks may remain active until the update that blocks their malicious flow is enforced. MITO computes a schedule that applies the most useful firewall changes first, according to the impact of the attacks they mitigate.

MITO combines automation, formal correctness and optimization by formulating the scheduling problem as a partial weighted Maximum Satisfiability Modulo Theories (MaxSMT) problem.

### Input and Output

The MITO framework takes as inputs:
* a Pre-Update Service Graph, representing the network and firewall configuration before the reconfiguration;
* a Post-Update Service Graph, representing the network and firewall configuration after the reconfiguration;
* a set of Attack Mitigation Requirements (AMRs), describing the malicious flows that must be blocked and their impact information;
* an application mode (economic or privacy mode), used to select the optimization criterion. The economic mode maximizes the cumulative mitigated impact during the transient, whereas the privacy mode gives strict priority to the highest-impact attacks.

After receiving these inputs, MITO solves the transient optimization problem. The output is an ordered schedule of firewall reconfiguration changes, such as:
* deployment of a new firewall instance;
* removal of an existing firewall instance;
* update of the filtering policy of an existing firewall.

### Impact Assessment

Each AMR is associated with an impact value computed from three parameters:
* asset value;
* vulnerability exploitation severity;
* attack strength.

## MITO Dependencies

The MITO framework requires the following dependencies to correctly work:
* Java SE Development Kit 8 or higher;
* Apache Maven;
* Z3.

### Z3 library support

Z3 is the solver used by MITO to solve the MaxSMT problem.

Download the correct version of Z3 according to your operating system and JVM. The Z3 native library must be included in the Java Library Path. The most convenient way to do this is to add the library path to the dynamic linking library path, which is:
* in Linux: `LD_LIBRARY_PATH`
* in MacOS: `DYLD_LIBRARY_PATH`
* in Windows: `PATH`

> e.g., on Linux,
> * `sudo nano /etc/environment`
> * `LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/MITO/z3/bin/`

A new environment variable, named Z3, can also be created:
> * `Z3=/home/MITO/z3/bin/`

## MITO Installation

The MITO framework can be installed via Maven.

### Installing MITO via Maven

* install Java;
* install Maven;
* install and configure Z3;
* clone the repository;
* compile the project:

```bash
mvn clean package
```

* run the application:

```bash
java -jar target/mito-0.0.1-SNAPSHOT.jar
```

### Running MITO locally from Main

The class `it.polito.mito.Main` can be used to execute MITO locally, without using the REST APIs. This mode is useful for testing a single XML scenario from the repository.

Put the XML file inside the `testfile/MITO/` folder. For example:

```text
testfile/MITO/Mito01.xml
```

Then, in `Main.java`, set the input file path in the `FileInputStream` used to create the `MitoSerializer`:

```java
MitoSerializer test = new MitoSerializer(
    (NFV) u.unmarshal(new FileInputStream("./testfile/MITO/Mito01.xml"))
);
```

To test a different file, replace `Mito01.xml` with the name of the XML scenario to execute.

The local main can be launched from the IDE by running:

```text
src/it/polito/mito/Main.java
```

as a Java application.


## REST APIs

MITO exposes REST APIs that can be used by external users, automatic firewall reconfiguration tools or network orchestrators.

### Connecting to the REST APIs

Follow these steps to boot the environment and use the APIs:

* configure Java and Z3;
* compile the project with Maven:

```bash
mvn clean package
```

* run the application:

```bash
java -jar target/mito-0.0.1-SNAPSHOT.jar
```

* interact with the REST APIs using any RESTful client.

The input can be provided in XML/JSON format, according to the representation adopted by the framework.

### MITO Interaction

Once the application is running, MITO is available at:

```text
http://localhost:8085/mito
```

To run a simulation, send a `POST` request to:

```text
POST http://localhost:8085/mito/adp/simulations
Content-Type: application/xml
```

The request body must contain a complete `NFV` document, including the service graphs and the properties required by the simulation.

If the request is accepted, MITO returns:
* HTTP status `201 Created`;
* the optimized NFV result in the response body;
* a `Location` header pointing to the stored simulation result.


## Support

If you need any kind of clarification, or you want to report a bug found in the code, you can contact us at: _<daniele.bringhenti@polito.it>_.
