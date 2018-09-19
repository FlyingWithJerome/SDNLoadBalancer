## A Simple SDN Load Balancer (and a Middlebox)

#### Prerequisites:

The following softwares/third party libraries should be properlly installed before running the application. The application is platform-independent, but these softwares might be platform-aware.

| Software/3rd Party Library Name | Version                                  | For what?                      |
| ------------------------------- | ---------------------------------------- | ------------------------------ |
| Python                          | 3.4 or above                             | language support               |
| ryu                             | 4.28 (a lower version may also be supported, but had not been tested) | controller to switch interface |
| mininet                         | 2.2.2                                    | network virtualization         |
| Open vswitch                    | 2.7.0                                    | virtual switch                 |

Known Problems:

1. Some previous releases of Open vswitch (older than 2.7.0) may crash in an eight-host virtual network, due to the segmentation fault. 

   ​

#### Files:

Two files are critical to this application. They are:

| File Name      | For what?                                |
| -------------- | ---------------------------------------- |
| lb.py          | The implementation of the load balancer  |
| lb_config.json | An example of the config file in JSON format |



#### Usage: 

There are two ways to run the load balancer. Run the following command in the terminal:

```bash
ryu-manager <directory_to_lb.py> --test-switch-dir <directory_to_lb_config.json>
```

If your ryu/flags.py has a different setup, or you prefer/have to run the load balancer in a pipeline, the load balancer also supports passing the file contents from STDIN, like this:

```bash
cat <directory_to_lb_config.json> | ryu-manager <directory_to_lb.py>
```

If the either command above is successful, the application will listen at port 6653. You can then (or before) launch a mininet instance, for example:

```bash
sudo mn --topo single,8 --mac --switch ovsk --controller remote
```

***Please be note that the load balancer application uses "—test-switch-dir" flag to take the file directory from the command line.***

The load balancer application have two working modes, proactive and reactive modes. You may switch the working mode by directly changing line 45 of the lb.py:

```python
_PROACTIVE_MODE = True # False for reactive mode
```

##### Proactive Mode:

​	Proactive mode uses flow entries to control the network flows from client to switch and switch to servers. It is faster: for the client -> switch -> server ping request, the response time can be at 0.01 to 0.1 ms level. However, the first two ping requests/responses might take longer than the rests.

##### Reactive Mode:

​	Reactive mode only uses a default flow entry to make sure that all the packets will be forwarded to the controller. No extra entry will be inserted, and all the traffic will be processed by the controller on a per-packet basis. It is slow: for the client -> switch -> server ping request, the response time is usually at 1 to 10 ms level.

​	Please also note that the reactive mode will generate much more logs than the proactive mode:

```
[2018-09-18 12:42:57,397] - INFO - Has an ARP (10.0.0.5 asking for 10.0.0.1)
[2018-09-18 12:42:57,400] - INFO - Get a server packet from 10.0.0.5 --> 10.0.0.1
[2018-09-18 12:42:57,400] - INFO - Forward packet 10.1.2.3 --> 10.0.0.1
[2018-09-18 12:42:58,396] - INFO - Get a client packet from 10.0.0.1 --> 10.1.2.3
[2018-09-18 12:42:58,396] - INFO - Forward packet 10.0.0.1 --> 10.0.0.5
[2018-09-18 12:42:58,398] - INFO - Get a server packet from 10.0.0.5 --> 10.0.0.1
[2018-09-18 12:42:58,399] - INFO - Forward packet 10.1.2.3 --> 10.0.0.1
[2018-09-18 12:42:59,400] - INFO - Get a client packet from 10.0.0.1 --> 10.1.2.3
[2018-09-18 12:42:59,401] - INFO - Forward packet 10.0.0.1 --> 10.0.0.6
...
```

​	All the traffics will be recorded to the log.

##### Which Mode Should I Choose, Proactive or Reactive?

​	If you are using a stateful protocol (e.g., TCP), or the packets are sensitive to the context, proactive mode is then highly recommended. Since reactive mode processes each packet seperately; two consecutive packets in a session may be forwarded to two different servers.

​	However, proactive mode uses flow entries to control the traffics. A client that has a long, intensive connection may severly impose stress to one single server while other peer servers are idling.