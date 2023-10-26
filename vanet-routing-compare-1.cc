#include <ctime>
#include <fstream>
#include <iostream>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/aodv-module.h"
#include "ns3/olsr-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"
#include "ns3/applications-module.h"
#include "ns3/itu-r-1411-los-propagation-loss-model.h"
#include "ns3/ocb-wifi-mac.h"
#include "ns3/wifi-80211p-helper.h"
#include "ns3/wave-mac-helper.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/config-store-module.h"
#include "ns3/integer.h"
#include "ns3/wave-helper.h"
#include "ns3/yans-wifi-helper.h"

#include "ns3/wifi-module.h"
#include "ns3/wifi-mac-header.h"
#include "ns3/ethernet-header.h"

#include "ns3/tag.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"

using namespace ns3;
using namespace dsr;

NS_LOG_COMPONENT_DEFINE("vanet-routing-compare");

/*




추가 - 1




*/

class FlagTag : public Tag
{
public:
  static TypeId GetTypeId(void);
  virtual TypeId GetInstanceTypeId(void) const;
  virtual uint32_t GetSerializedSize(void) const;
  virtual void Serialize(TagBuffer i) const;
  virtual void Deserialize(TagBuffer i);
  virtual void Print(std::ostream &os) const;

  void SetSimpleValue(uint8_t value);
  uint8_t GetSimpleValue(void) const;

private:
  uint8_t m_simpleValue;
};

TypeId
FlagTag::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::FlagTag")
                          .SetParent<Tag>()
                          .AddConstructor<FlagTag>()
                          .AddAttribute("SimpleValue",
                                        "A simple value",
                                        EmptyAttributeValue(),
                                        MakeUintegerAccessor(&FlagTag::GetSimpleValue),
                                        MakeUintegerChecker<uint8_t>());
  return tid;
}

TypeId
FlagTag::GetInstanceTypeId(void) const
{
  return GetTypeId();
}

uint32_t
FlagTag::GetSerializedSize(void) const
{
  return 1;
}

void FlagTag::Serialize(TagBuffer i) const
{
  i.WriteU8(m_simpleValue);
}

void FlagTag::Deserialize(TagBuffer i)
{
  m_simpleValue = i.ReadU8();
}

void FlagTag::Print(std::ostream &os) const
{
  os << "v=" << (uint32_t)m_simpleValue;
}

void FlagTag::SetSimpleValue(uint8_t value)
{
  m_simpleValue = value;
}

uint8_t
FlagTag::GetSimpleValue(void) const
{
  return m_simpleValue;
}

/*




추가 - 1




*/

class RoutingStats
{
public:
  RoutingStats();
  uint32_t GetRxBytes();
  uint32_t GetCumulativeRxBytes();
  uint32_t GetRxPkts();
  uint32_t GetCumulativeRxPkts();
  void IncRxBytes(uint32_t rxBytes);
  void IncRxPkts();
  void SetRxBytes(uint32_t rxBytes);
  void SetRxPkts(uint32_t rxPkts);
  uint32_t GetTxBytes();
  uint32_t GetCumulativeTxBytes();
  uint32_t GetTxPkts();
  uint32_t GetCumulativeTxPkts();
  void IncTxBytes(uint32_t txBytes);
  void IncTxPkts();
  void SetTxBytes(uint32_t txBytes);
  void SetTxPkts(uint32_t txPkts);

private:
  uint32_t m_RxBytes;
  uint32_t m_cumulativeRxBytes;
  uint32_t m_RxPkts;
  uint32_t m_cumulativeRxPkts;
  uint32_t m_TxBytes;
  uint32_t m_cumulativeTxBytes;
  uint32_t m_TxPkts;
  uint32_t m_cumulativeTxPkts;
};

RoutingStats::RoutingStats()
    : m_RxBytes(0),
      m_cumulativeRxBytes(0),
      m_RxPkts(0),
      m_cumulativeRxPkts(0),
      m_TxBytes(0),
      m_cumulativeTxBytes(0),
      m_TxPkts(0),
      m_cumulativeTxPkts(0)
{
}

uint32_t
RoutingStats::GetRxBytes()
{
  return m_RxBytes;
}

uint32_t
RoutingStats::GetCumulativeRxBytes()
{
  return m_cumulativeRxBytes;
}

uint32_t
RoutingStats::GetRxPkts()
{
  return m_RxPkts;
}

uint32_t
RoutingStats::GetCumulativeRxPkts()
{
  return m_cumulativeRxPkts;
}

void RoutingStats::IncRxBytes(uint32_t rxBytes)
{
  m_RxBytes += rxBytes;
  m_cumulativeRxBytes += rxBytes;
}

void RoutingStats::IncRxPkts()
{
  m_RxPkts++;
  m_cumulativeRxPkts++;
}

void RoutingStats::SetRxBytes(uint32_t rxBytes)
{
  m_RxBytes = rxBytes;
}

void RoutingStats::SetRxPkts(uint32_t rxPkts)
{
  m_RxPkts = rxPkts;
}

uint32_t
RoutingStats::GetTxBytes()
{
  return m_TxBytes;
}

uint32_t
RoutingStats::GetCumulativeTxBytes()
{
  return m_cumulativeTxBytes;
}

uint32_t
RoutingStats::GetTxPkts()
{
  return m_TxPkts;
}

uint32_t
RoutingStats::GetCumulativeTxPkts()
{
  return m_cumulativeTxPkts;
}

void RoutingStats::IncTxBytes(uint32_t txBytes)
{
  m_TxBytes += txBytes;
  m_cumulativeTxBytes += txBytes;
}

void RoutingStats::IncTxPkts()
{
  m_TxPkts++;
  m_cumulativeTxPkts++;
}

void RoutingStats::SetTxBytes(uint32_t txBytes)
{
  m_TxBytes = txBytes;
}

void RoutingStats::SetTxPkts(uint32_t txPkts)
{
  m_TxPkts = txPkts;
}
class RoutingHelper : public Object
{
public:
  static TypeId GetTypeId(void);
  RoutingHelper();
  virtual ~RoutingHelper();
  void Install(NodeContainer &c,
               NetDeviceContainer &d,
               Ipv4InterfaceContainer &i,
               double totalTime,
               int protocol,
               uint32_t nSinks,
               int routingTables);
  void OnOffTrace(std::string context, Ptr<const Packet> packet);
  RoutingStats &GetRoutingStats();
  void SetLogging(int log);

private:
  void SetupRoutingProtocol(NodeContainer &c);
  void AssignIpAddresses(NetDeviceContainer &d,
                         Ipv4InterfaceContainer &adhocTxInterfaces);
  void SetupRoutingMessages(NodeContainer &c,
                            Ipv4InterfaceContainer &adhocTxInterfaces);
  Ptr<Socket> SetupRoutingPacketReceive(Ipv4Address addr, Ptr<Node> node);
  void ReceiveRoutingPacket(Ptr<Socket> socket);

  double m_TotalSimTime;
  uint32_t m_protocol;
  uint32_t m_port;
  uint32_t m_nSinks;
  int m_routingTables;
  RoutingStats routingStats;
  std::string m_protocolName;
  int m_log;
};

NS_OBJECT_ENSURE_REGISTERED(RoutingHelper);

TypeId
RoutingHelper::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::RoutingHelper")
                          .SetParent<Object>()
                          .AddConstructor<RoutingHelper>();
  return tid;
}

RoutingHelper::RoutingHelper()
    : m_TotalSimTime(0),
      m_protocol(0),
      m_port(9),
      m_nSinks(0),
      m_routingTables(0),
      m_log(0)
{
}

RoutingHelper::~RoutingHelper()
{
}

void RoutingHelper::Install(NodeContainer &c,
                            NetDeviceContainer &d,
                            Ipv4InterfaceContainer &i,
                            double totalTime,
                            int protocol,
                            uint32_t nSinks,
                            int routingTables)
{
  m_TotalSimTime = totalTime;
  m_protocol = protocol;
  m_nSinks = nSinks;
  m_routingTables = routingTables;

  SetupRoutingProtocol(c);
  AssignIpAddresses(d, i);
  SetupRoutingMessages(c, i);
}

Ptr<Socket> RoutingHelper::SetupRoutingPacketReceive(Ipv4Address addr, Ptr<Node> node)
{
  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  Ptr<Socket> sink = Socket::CreateSocket(node, tid);
  InetSocketAddress local = InetSocketAddress(addr, m_port);
  sink->Bind(local);
  sink->SetRecvCallback(MakeCallback(&RoutingHelper::ReceiveRoutingPacket, this));

  return sink;
}

void RoutingHelper::SetupRoutingProtocol(NodeContainer &c)
{
  AodvHelper aodv;
  OlsrHelper olsr;
  DsdvHelper dsdv;
  DsrHelper dsr;
  DsrMainHelper dsrMain;
  Ipv4ListRoutingHelper list;
  InternetStackHelper internet;

  Time rtt = Time(5.0);
  AsciiTraceHelper ascii;
  Ptr<OutputStreamWrapper> rtw = ascii.CreateFileStream("routing_table");

  switch (m_protocol)
  {
  case 0:
    m_protocolName = "NONE";
    break;
  case 1:
    if (m_routingTables != 0)
    {
      olsr.PrintRoutingTableAllAt(rtt, rtw);
    }
    list.Add(olsr, 1);
    m_protocolName = "OLSR";

    break;
  case 2:
    if (m_routingTables != 0)
    {
      aodv.PrintRoutingTableAllAt(rtt, rtw);
    }
    list.Add(aodv, 100);
    m_protocolName = "AODV";
    break;
  case 3:
    if (m_routingTables != 0)
    {
      dsdv.PrintRoutingTableAllAt(rtt, rtw);
    }
    list.Add(dsdv, 100);
    m_protocolName = "DSDV";
    break;
  default:
    NS_FATAL_ERROR("No such protocol:" << m_protocol);
    break;
  }

  if (m_protocol < 4)
  {
    internet.SetRoutingHelper(list);
    internet.Install(c);
  }
  else if (m_protocol == 4)
  {
    internet.Install(c);
    dsrMain.Install(dsr, c);
  }

  if (m_log != 0)
  {
    NS_LOG_UNCOND("Routing Setup for " << m_protocolName);
  }
}

void RoutingHelper::AssignIpAddresses(NetDeviceContainer &d,
                                      Ipv4InterfaceContainer &adhocTxInterfaces)
{
  NS_LOG_INFO("Assigning IP addresses");
  Ipv4AddressHelper addressAdhoc;
  addressAdhoc.SetBase("10.1.0.0", "255.255.0.0");
  adhocTxInterfaces = addressAdhoc.Assign(d);
}
void RoutingHelper::SetupRoutingMessages(NodeContainer &c,
                                         Ipv4InterfaceContainer &adhocTxInterfaces)
{
  OnOffHelper onoff1("ns3::UdpSocketFactory", Address());
  onoff1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1.0]"));
  onoff1.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));

  Ptr<UniformRandomVariable> var = CreateObject<UniformRandomVariable>();
  int64_t stream = 2;
  var->SetStream(stream);

  for (uint32_t i = 1; i < m_nSinks; i++)
  {
    Ptr<Socket> sink = SetupRoutingPacketReceive(adhocTxInterfaces.GetAddress(i), c.Get(i));
    AddressValue remoteAddress(InetSocketAddress(adhocTxInterfaces.GetAddress(i), m_port));
    onoff1.SetAttribute("Remote", remoteAddress);
  }
  for (uint32_t i = 0; i < 2; i++)
  {
    ApplicationContainer temp = onoff1.Install(c.Get(i));
    temp.Start(Seconds(var->GetValue(1.0, 2.0)));
    temp.Stop(Seconds(m_TotalSimTime));
  }
}

static inline std::string
PrintReceivedRoutingPacket(Ptr<Socket> socket, Ptr<Packet> packet, Address srcAddress)
{
  std::ostringstream oss;

  oss << Simulator::Now().GetSeconds() << " " << socket->GetNode()->GetId();

  if (InetSocketAddress::IsMatchingType(srcAddress))
  {
    InetSocketAddress addr = InetSocketAddress::ConvertFrom(srcAddress);
    oss << " received one packet from " << addr.GetIpv4();
    std::cout << " received one packet from " << addr.GetIpv4() << std::endl;
  }
  else
  {
    oss << " received one packet!";
    std::cout << " received one packet!" << std::endl;
  }
  return oss.str();
}

void RoutingHelper::ReceiveRoutingPacket(Ptr<Socket> socket)
{
  Ptr<Packet> packet;
  Address srcAddress;
  while ((packet = socket->RecvFrom(srcAddress)))
  {
    std::cout << srcAddress << std::endl;

    uint32_t RxRoutingBytes = packet->GetSize();

    FlagTag tag;
    tag.SetSimpleValue(0x56);
    packet->AddPacketTag(tag);

    GetRoutingStats().IncRxBytes(RxRoutingBytes);
    GetRoutingStats().IncRxPkts();
  }
}

void RoutingHelper::OnOffTrace(std::string context, Ptr<const Packet> packet)
{
  uint32_t pktBytes = packet->GetSize();

  routingStats.IncTxBytes(pktBytes);
}

RoutingStats &
RoutingHelper::GetRoutingStats()
{
  return routingStats;
}

void RoutingHelper::SetLogging(int log)
{
  m_log = log;
}
class WifiPhyStats : public Object
{
public:
  static TypeId GetTypeId(void);
  WifiPhyStats();
  virtual ~WifiPhyStats();
  uint32_t GetTxBytes();
  void PhyTxTrace(std::string context, Ptr<const Packet> packet, WifiMode mode, WifiPreamble preamble, uint8_t txPower);
  void PhyTxDrop(std::string context, Ptr<const Packet> packet);
  void PhyRxDrop(std::string context, Ptr<const Packet> packet);

private:
  uint32_t m_phyTxPkts;
  uint32_t m_phyTxBytes;
};

NS_OBJECT_ENSURE_REGISTERED(WifiPhyStats);

TypeId
WifiPhyStats::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::WifiPhyStats")
                          .SetParent<Object>()
                          .AddConstructor<WifiPhyStats>();
  return tid;
}

WifiPhyStats::WifiPhyStats()
    : m_phyTxPkts(0),
      m_phyTxBytes(0)
{
}

WifiPhyStats::~WifiPhyStats()
{
}

void WifiPhyStats::PhyTxTrace(std::string context, Ptr<const Packet> packet, WifiMode mode, WifiPreamble preamble, uint8_t txPower)
{
  WifiMacHeader wifiMacHeader;
  NS_LOG_FUNCTION(this << context << packet << "PHYTX mode=" << mode);
  ++m_phyTxPkts;
  uint32_t pktSize = packet->GetSize();
  m_phyTxBytes += pktSize;

  //std::cout << packet->GetSize() << std::endl;
  //std::cout << packet->PeekHeader(wifiMacHeader) << std::endl;

  /*




  수정 - 1




  */

  //NS_ASSERT(tagCopy.GetSimpleValue() == tag.GetSimpleValue());

  //aCopy->PrintPacketTags(std::cout);
  //std::cout << std::endl;

  //std::cout << "Packet->PeekPacketTag : " << packet->PeekPacketTag(tag) << std::endl;

  // packet->AddPacketTag("A");
  // std::cout << packet->PeekPacketTag() << std::endl;
}

void WifiPhyStats::PhyTxDrop(std::string context, Ptr<const Packet> packet)
{
  NS_LOG_UNCOND("PHY Tx Drop");
}

void WifiPhyStats::PhyRxDrop(std::string context, Ptr<const Packet> packet)
{
  NS_LOG_UNCOND("PHY Rx Drop");
}

uint32_t
WifiPhyStats::GetTxBytes()
{
  return m_phyTxBytes;
}
class WifiApp
{
public:
  WifiApp();
  virtual ~WifiApp();
  void Simulate(int argc, char **argv);

protected:
  virtual void SetDefaultAttributeValues();
  virtual void ParseCommandLineArguments(int argc, char **argv);
  virtual void ConfigureNodes();
  virtual void ConfigureChannels();
  virtual void ConfigureDevices();
  virtual void ConfigureMobility();
  virtual void ConfigureApplications();
  virtual void ConfigureTracing();
  virtual void RunSimulation();
};

WifiApp::WifiApp()
{
}

WifiApp::~WifiApp()
{
}

void WifiApp::Simulate(int argc, char **argv)
{
  SetDefaultAttributeValues();
  ParseCommandLineArguments(argc, argv);
  ConfigureNodes();
  ConfigureChannels();
  ConfigureDevices();
  ConfigureMobility();
  ConfigureApplications();
  ConfigureTracing();
  RunSimulation();
}

void WifiApp::SetDefaultAttributeValues() {}
void WifiApp::ParseCommandLineArguments(int argc, char **argv) {}
void WifiApp::ConfigureNodes() {}
void WifiApp::ConfigureChannels() {}
void WifiApp::ConfigureDevices() {}
void WifiApp::ConfigureMobility() {}
void WifiApp::ConfigureApplications() {}
void WifiApp::ConfigureTracing() {}
void WifiApp::RunSimulation() {}

class ConfigStoreHelper
{
public:
  ConfigStoreHelper();
  void LoadConfig(std::string configFilename);
  void SaveConfig(std::string configFilename);
};

ConfigStoreHelper::ConfigStoreHelper()
{
}

void ConfigStoreHelper::LoadConfig(std::string configFilename)
{
  Config::SetDefault("ns3::ConfigStore::Filename", StringValue(configFilename));
  Config::SetDefault("ns3::ConfigStore::FileFormat", StringValue("RawText"));
  Config::SetDefault("ns3::ConfigStore::Mode", StringValue("Load"));
  ConfigStore inputConfig;
  inputConfig.ConfigureDefaults();
}

void ConfigStoreHelper::SaveConfig(std::string configFilename)
{
  if (configFilename.compare("") != 0)
  {
    Config::SetDefault("ns3::ConfigStore::Filename", StringValue(configFilename));
    Config::SetDefault("ns3::ConfigStore::FileFormat", StringValue("RawText"));
    Config::SetDefault("ns3::ConfigStore::Mode", StringValue("Save"));
    ConfigStore outputConfig;
    outputConfig.ConfigureDefaults();
  }
}
class VanetRoutingExperiment : public WifiApp
{
public:
  VanetRoutingExperiment();

protected:
  virtual void SetDefaultAttributeValues();
  virtual void ParseCommandLineArguments(int argc, char **argv);
  virtual void ConfigureNodes();
  virtual void ConfigureChannels();
  virtual void ConfigureDevices();
  virtual void ConfigureMobility();
  virtual void ConfigureApplications();
  virtual void ConfigureTracing();
  virtual void RunSimulation();

private:
  void Run();
  void CommandSetup(int argc, char **argv);
  void SetupLogFile();
  void SetupLogging();
  void ConfigureDefaults();
  void SetupAdhocMobilityNodes();
  void SetupAdhocDevices();
  void SetupRoutingMessages();
  void SetupScenario();
  void SetConfigFromGlobals();
  void SetGlobalsFromConfig();

  /*

  수정 - 1

  */

  uint32_t m_port;
  std::string m_CSVfileName;
  std::string m_CSVfileName2;
  uint32_t m_nSinks;
  std::string m_protocolName;
  double m_txp;
  bool m_traceMobility;
  uint32_t m_protocol;

  uint32_t m_lossModel;
  uint32_t m_fading;
  std::string m_lossModelName;

  std::string m_phyMode;
  uint32_t m_80211mode;

  std::string m_traceFile;
  std::string m_logFile;
  uint32_t m_mobility;
  uint32_t m_nNodes;
  double m_TotalSimTime;
  std::string m_rate;
  std::string m_phyModeB;
  std::string m_trName;
  int m_nodeSpeed;
  int m_nodePause;
  uint32_t m_wavePacketSize;
  double m_waveInterval;
  int m_verbose;
  std::ofstream m_os;
  NetDeviceContainer m_adhocTxDevices;
  Ipv4InterfaceContainer m_adhocTxInterfaces;
  double m_gpsAccuracyNs;
  double m_txMaxDelayMs;
  int m_routingTables;
  int m_asciiTrace;
  int m_pcap;
  std::string m_loadConfigFilename;
  std::string m_saveConfigFilename;

  Ptr<RoutingHelper> m_routingHelper;
  Ptr<WifiPhyStats> m_wifiPhyStats;
  int m_log;
  int64_t m_streamIndex;
  NodeContainer m_adhocTxNodes;
  std::string m_exp;
};

VanetRoutingExperiment::VanetRoutingExperiment()
    : m_port(9),
      m_CSVfileName("vanet-routing.output.csv"),
      m_CSVfileName2("vanet-routing.output2.csv"),
      m_nSinks(0),
      m_protocolName("protocol"),
      m_txp(20),
      m_traceMobility(false),
      m_protocol(2),
      m_lossModel(3),
      m_fading(0),
      m_lossModelName(""),
      m_phyMode("OfdmRate6MbpsBW10MHz"),
      m_80211mode(1),
      m_traceFile("/home/whdgus1323/Sumo/TCL/modified.tcl"),
      m_logFile("low99-ct-unterstrass-1day.filt.7.adj.log"),
      m_mobility(1),
      m_TotalSimTime(0),
      m_rate("2048bps"),
      m_phyModeB("DsssRate11Mbps"),
      m_trName("vanet-routing-compare"),
      m_nodeSpeed(20),
      m_nodePause(0),
      m_wavePacketSize(200),
      m_waveInterval(0.1),
      m_verbose(1),
      m_gpsAccuracyNs(40),
      m_txMaxDelayMs(10),
      m_routingTables(0),
      m_asciiTrace(0),
      m_pcap(0),
      m_loadConfigFilename("load-config.txt"),
      m_saveConfigFilename(""),
      m_log(0),
      m_streamIndex(0),
      m_adhocTxNodes(),
      m_exp("")
{
  m_wifiPhyStats = CreateObject<WifiPhyStats>();
  m_routingHelper = CreateObject<RoutingHelper>();
  m_log = 1;
}

void VanetRoutingExperiment::SetDefaultAttributeValues()
{
}

static ns3::GlobalValue g_port("VRCport", "Port", ns3::UintegerValue(9), ns3::MakeUintegerChecker<uint32_t>());

static ns3::GlobalValue g_nSinks("VRCnSinks", "Number of sink nodes for routing non-BSM traffic", ns3::UintegerValue(10), ns3::MakeUintegerChecker<uint32_t>());

static ns3::GlobalValue g_traceMobility("VRCtraceMobility", "Trace mobility 1=yes;0=no", ns3::UintegerValue(0), ns3::MakeUintegerChecker<uint32_t>());
static ns3::GlobalValue g_protocol("VRCprotocol", "Routing protocol", ns3::UintegerValue(2), ns3::MakeUintegerChecker<uint32_t>());
static ns3::GlobalValue g_lossModel("VRClossModel", "Propagation Loss Model", ns3::UintegerValue(3), ns3::MakeUintegerChecker<uint32_t>());
static ns3::GlobalValue g_fading("VRCfading", "Fast Fading Model", ns3::UintegerValue(0), ns3::MakeUintegerChecker<uint32_t>());
static ns3::GlobalValue g_80211mode("VRC80211mode", "802.11 mode (0=802.11a;1=802.11p)", ns3::UintegerValue(1), ns3::MakeUintegerChecker<uint32_t>());
static ns3::GlobalValue g_mobility("VRCmobility", "Mobility mode 0=random waypoint;1=mobility trace file", ns3::UintegerValue(1), ns3::MakeUintegerChecker<uint32_t>());
static ns3::GlobalValue g_nNodes("VRCnNodes", "Number of nodes (vehicles)", ns3::UintegerValue(156), ns3::MakeUintegerChecker<uint32_t>());
static ns3::GlobalValue g_nodeSpeed("VRCnodeSpeed", "Node speed (m/s) for RWP model", ns3::UintegerValue(20), ns3::MakeUintegerChecker<uint32_t>());
static ns3::GlobalValue g_nodePause("VRCnodePause", "Node pause time (s) for RWP model", ns3::UintegerValue(0), ns3::MakeUintegerChecker<uint32_t>());

static ns3::GlobalValue g_wavePacketSize("VRCwavePacketSize", "Size in bytes of WAVE BSM", ns3::UintegerValue(200), ns3::MakeUintegerChecker<uint32_t>());

static ns3::GlobalValue g_verbose("VRCverbose", "Verbose 0=no;1=yes", ns3::UintegerValue(0), ns3::MakeUintegerChecker<uint32_t>());
static ns3::GlobalValue g_scenario("VRCscenario", "Scenario", ns3::UintegerValue(1), ns3::MakeUintegerChecker<uint32_t>());
static ns3::GlobalValue g_routingTables("VRCroutingTables", "Dump routing tables at t=5 seconds 0=no;1=yes", ns3::UintegerValue(0), ns3::MakeUintegerChecker<uint32_t>());
static ns3::GlobalValue g_asciiTrace("VRCasciiTrace", "Dump ASCII trace 0=no;1=yes", ns3::UintegerValue(0), ns3::MakeUintegerChecker<uint32_t>());
static ns3::GlobalValue g_pcap("VRCpcap", "Generate PCAP files 0=no;1=yes", ns3::UintegerValue(1), ns3::MakeUintegerChecker<uint32_t>());

static ns3::GlobalValue g_txp("VRCtxp", "Transmission power dBm", ns3::DoubleValue(7.5), ns3::MakeDoubleChecker<double>());
static ns3::GlobalValue g_totalTime("VRCtotalTime", "Total simulation time (s)", ns3::DoubleValue(300.01), ns3::MakeDoubleChecker<double>());

static ns3::GlobalValue g_waveInterval("VRCwaveInterval", "Interval (s) between WAVE BSMs", ns3::DoubleValue(0.1), ns3::MakeDoubleChecker<double>());

static ns3::GlobalValue g_gpsAccuracyNs("VRCgpsAccuracyNs", "GPS sync accuracy (ns)", ns3::DoubleValue(40), ns3::MakeDoubleChecker<double>());
static ns3::GlobalValue g_txMaxDelayMs("VRCtxMaxDelayMs", "Tx May Delay (ms)", ns3::DoubleValue(10), ns3::MakeDoubleChecker<double>());
static ns3::GlobalValue g_CSVfileName("VRCCSVfileName", "CSV filename (for time series data)", ns3::StringValue("vanet-routing.output.csv"), ns3::MakeStringChecker());
static ns3::GlobalValue g_CSVfileName2("VRCCSVfileName2", "CSV filename 2 (for overall simulation scenario results)", ns3::StringValue("vanet-routing.output2.csv"), ns3::MakeStringChecker());
static ns3::GlobalValue g_phyMode("VRCphyMode", "PHY mode (802.11p)", ns3::StringValue("OfdmRate6MbpsBW10MHz"), ns3::MakeStringChecker());
static ns3::GlobalValue g_traceFile("VRCtraceFile", "Mobility trace filename", ns3::StringValue("./src/wave/examples/low99-ct-unterstrass-1day.filt.7.adj.mob"), ns3::MakeStringChecker());
static ns3::GlobalValue g_logFile("VRClogFile", "Log filename", ns3::StringValue("low99-ct-unterstrass-1day.filt.7.adj.log"), ns3::MakeStringChecker());
static ns3::GlobalValue g_rate("VRCrate", "Data rate", ns3::StringValue("2048bps"), ns3::MakeStringChecker());
static ns3::GlobalValue g_phyModeB("VRCphyModeB", "PHY mode (802.11a)", ns3::StringValue("DsssRate11Mbps"), ns3::MakeStringChecker());
static ns3::GlobalValue g_trName("VRCtrName", "Trace name", ns3::StringValue("vanet-routing-compare"), ns3::MakeStringChecker());

void VanetRoutingExperiment::ParseCommandLineArguments(int argc, char **argv)
{
  CommandSetup(argc, argv);
  SetupScenario();

  ConfigureDefaults();

  SetGlobalsFromConfig();
  ConfigStoreHelper configStoreHelper;
  configStoreHelper.SaveConfig(m_saveConfigFilename);
  m_routingHelper->SetLogging(m_log);
}

void VanetRoutingExperiment::ConfigureNodes()
{
  m_adhocTxNodes.Create(m_nNodes);
}

void VanetRoutingExperiment::ConfigureChannels()
{
  SetupAdhocDevices();
}

void VanetRoutingExperiment::ConfigureDevices()
{
  Config::Connect("/NodeList/*/DeviceList/*/Phy/State/Tx", MakeCallback(&WifiPhyStats::PhyTxTrace, m_wifiPhyStats));
  Config::Connect("/NodeList/*/DeviceList/*/ns3::WifiNetDevice/Phy/PhyTxDrop", MakeCallback(&WifiPhyStats::PhyTxDrop, m_wifiPhyStats));
  Config::Connect("/NodeList/*/DeviceList/*/ns3::WifiNetDevice/Phy/PhyRxDrop", MakeCallback(&WifiPhyStats::PhyRxDrop, m_wifiPhyStats));
}

void VanetRoutingExperiment::ConfigureMobility()
{
  SetupAdhocMobilityNodes();
}

void VanetRoutingExperiment::ConfigureApplications()
{
  SetupRoutingMessages();

  std::ostringstream oss;
  oss.str("");
  oss << "/NodeList/*/ApplicationList/*/$ns3::OnOffApplication/Tx";
  Config::Connect(oss.str(), MakeCallback(&RoutingHelper::OnOffTrace, m_routingHelper));
}

void VanetRoutingExperiment::ConfigureTracing()
{
  SetupLogFile();
  SetupLogging();

  AsciiTraceHelper ascii;
  MobilityHelper::EnableAsciiAll(ascii.CreateFileStream(m_trName + ".mob"));
}

void VanetRoutingExperiment::RunSimulation()
{
  Run();
}

void VanetRoutingExperiment::Run()
{
  NS_LOG_INFO("Run Simulation.");
  // AnimationInterface anim("Vanetanim.xml");

  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();

  Simulator::Stop(Seconds(m_TotalSimTime));
  Simulator::Run();

  uint32_t SentPackets = 0;
  uint32_t ReceivedPackets = 0;
  uint32_t LostPackets = 0;

  int j = 0;
  float AvgThroughput = 0;

  Time Jitter;
  Time Delay;

  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();

  /**/

  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter = stats.begin(); iter != stats.end(); ++iter)
  {
    Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(iter->first);

    
    NS_LOG_UNCOND("----Flow ID:" << iter->first);
    NS_LOG_UNCOND("Src Addr" << t.sourceAddress << "Dst Addr " << t.destinationAddress);
    NS_LOG_UNCOND("Sent Packets=" << iter->second.txPackets);
    NS_LOG_UNCOND("Received Packets =" << iter->second.rxPackets);
    NS_LOG_UNCOND("Lost Packets =" << iter->second.txPackets - iter->second.rxPackets);
    NS_LOG_UNCOND("Packet delivery ratio =" << iter->second.rxPackets * 100 / iter->second.txPackets << "%");
    NS_LOG_UNCOND("Packet loss ratio =" << (iter->second.txPackets - iter->second.rxPackets) * 100 / iter->second.txPackets << "%");
    NS_LOG_UNCOND("Delay =" << iter->second.delaySum);
    NS_LOG_UNCOND("Jitter =" << iter->second.jitterSum);
    NS_LOG_UNCOND("Throughput =" << iter->second.rxBytes * 8.0 / (iter->second.timeLastRxPacket.GetSeconds() - iter->second.timeFirstTxPacket.GetSeconds()) / 1024 << "Kbps");
    
    SentPackets = SentPackets + (iter->second.txPackets);
    ReceivedPackets = ReceivedPackets + (iter->second.rxPackets);
    LostPackets = LostPackets + (iter->second.txPackets - iter->second.rxPackets);
    AvgThroughput = AvgThroughput + (iter->second.rxBytes * 8.0 / (iter->second.timeLastRxPacket.GetSeconds() - iter->second.timeFirstTxPacket.GetSeconds()) / 1024);
    Delay = Delay + (iter->second.delaySum);
    Jitter = Jitter + (iter->second.jitterSum);

    j = j + 1;
  }

  AvgThroughput = AvgThroughput / j;

  NS_LOG_UNCOND("--------Total Results of the simulation----------" << std::endl);
  NS_LOG_UNCOND("Total sent packets  =" << SentPackets);
  NS_LOG_UNCOND("Total Received Packets =" << ReceivedPackets);
  NS_LOG_UNCOND("Total Lost Packets =" << LostPackets);
  NS_LOG_UNCOND("Packet Loss ratio =" << ((LostPackets * 100) / SentPackets) << "%");
  NS_LOG_UNCOND("Packet delivery ratio =" << ((ReceivedPackets * 100) / SentPackets) << "%");
  NS_LOG_UNCOND("Average Throughput =" << AvgThroughput << "Kbps");
  NS_LOG_UNCOND("End to End Delay =" << Delay);
  NS_LOG_UNCOND("End to End Jitter delay =" << Jitter);
  NS_LOG_UNCOND("Total Flod id " << j);
  
  monitor->SerializeToXmlFile("manet-routing.flowmon", true, true);

  Simulator::Destroy();
}

void VanetRoutingExperiment::SetConfigFromGlobals()
{
  UintegerValue uintegerValue;
  DoubleValue doubleValue;
  StringValue stringValue;

  GlobalValue::GetValueByName("VRCport", uintegerValue);
  m_port = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCnSinks", uintegerValue);
  m_nSinks = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCtraceMobility", uintegerValue);
  m_traceMobility = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCprotocol", uintegerValue);
  m_protocol = uintegerValue.Get();
  GlobalValue::GetValueByName("VRClossModel", uintegerValue);
  m_lossModel = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCfading", uintegerValue);
  m_fading = uintegerValue.Get();
  GlobalValue::GetValueByName("VRC80211mode", uintegerValue);
  m_80211mode = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCmobility", uintegerValue);
  m_mobility = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCnNodes", uintegerValue);
  m_nNodes = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCnodeSpeed", uintegerValue);
  m_nodeSpeed = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCnodePause", uintegerValue);
  m_nodePause = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCwavePacketSize", uintegerValue);
  m_wavePacketSize = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCverbose", uintegerValue);
  m_verbose = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCroutingTables", uintegerValue);
  m_routingTables = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCasciiTrace", uintegerValue);
  m_asciiTrace = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCpcap", uintegerValue);
  m_pcap = uintegerValue.Get();
  GlobalValue::GetValueByName("VRCtxp", doubleValue);
  m_txp = doubleValue.Get();
  GlobalValue::GetValueByName("VRCtotalTime", doubleValue);
  m_TotalSimTime = doubleValue.Get();
  GlobalValue::GetValueByName("VRCwaveInterval", doubleValue);
  m_waveInterval = doubleValue.Get();
  GlobalValue::GetValueByName("VRCgpsAccuracyNs", doubleValue);
  m_gpsAccuracyNs = doubleValue.Get();
  GlobalValue::GetValueByName("VRCtxMaxDelayMs", doubleValue);
  m_txMaxDelayMs = doubleValue.Get();

  GlobalValue::GetValueByName("VRCCSVfileName", stringValue);
  m_CSVfileName = stringValue.Get();
  GlobalValue::GetValueByName("VRCCSVfileName2", stringValue);
  m_CSVfileName2 = stringValue.Get();
  GlobalValue::GetValueByName("VRCphyMode", stringValue);
  m_phyMode = stringValue.Get();
  GlobalValue::GetValueByName("VRCtraceFile", stringValue);
  m_traceFile = stringValue.Get();
  GlobalValue::GetValueByName("VRClogFile", stringValue);
  m_logFile = stringValue.Get();
  GlobalValue::GetValueByName("VRCrate", stringValue);
  m_rate = stringValue.Get();
  GlobalValue::GetValueByName("VRCphyModeB", stringValue);
  m_phyModeB = stringValue.Get();
  GlobalValue::GetValueByName("VRCtrName", stringValue);
  m_trName = stringValue.Get();
}

void VanetRoutingExperiment::SetGlobalsFromConfig()
{
  UintegerValue uintegerValue;
  DoubleValue doubleValue;
  StringValue stringValue;

  g_port.SetValue(UintegerValue(m_port));
  g_nSinks.SetValue(UintegerValue(m_nSinks));
  g_traceMobility.SetValue(UintegerValue(m_traceMobility));
  g_protocol.SetValue(UintegerValue(m_protocol));
  g_lossModel.SetValue(UintegerValue(m_lossModel));
  g_fading.SetValue(UintegerValue(m_fading));
  g_80211mode.SetValue(UintegerValue(m_80211mode));
  g_mobility.SetValue(UintegerValue(m_mobility));
  g_nNodes.SetValue(UintegerValue(m_nNodes));
  g_nodeSpeed.SetValue(UintegerValue(m_nodeSpeed));
  g_nodePause.SetValue(UintegerValue(m_nodePause));
  g_wavePacketSize.SetValue(UintegerValue(m_wavePacketSize));
  g_verbose.SetValue(UintegerValue(m_verbose));
  g_routingTables.SetValue(UintegerValue(m_routingTables));
  g_asciiTrace.SetValue(UintegerValue(m_asciiTrace));
  g_pcap.SetValue(UintegerValue(m_pcap));

  g_txp.SetValue(DoubleValue(m_txp));
  g_totalTime.SetValue(DoubleValue(m_TotalSimTime));
  g_waveInterval.SetValue(DoubleValue(m_waveInterval));
  g_gpsAccuracyNs.SetValue(DoubleValue(m_gpsAccuracyNs));
  g_txMaxDelayMs.SetValue(DoubleValue(m_txMaxDelayMs));

  g_CSVfileName.SetValue(StringValue(m_CSVfileName));
  g_CSVfileName2.SetValue(StringValue(m_CSVfileName2));
  g_phyMode.SetValue(StringValue(m_phyMode));
  g_traceFile.SetValue(StringValue(m_traceFile));
  g_logFile.SetValue(StringValue(m_logFile));
  g_rate.SetValue(StringValue(m_rate));
  g_phyModeB.SetValue(StringValue(m_phyModeB));
  g_trName.SetValue(StringValue(m_trName));
  GlobalValue::GetValueByName("VRCtrName", stringValue);
  m_trName = stringValue.Get();
}

void VanetRoutingExperiment::CommandSetup(int argc, char **argv)
{
  CommandLine cmd;
  cmd.AddValue("CSVfileName", "The name of the CSV output file name", m_CSVfileName);
  cmd.AddValue("CSVfileName2", "The name of the CSV output file name2", m_CSVfileName2);
  cmd.AddValue("totaltime", "Simulation end time", m_TotalSimTime);
  cmd.AddValue("nodes", "Number of nodes (i.e. vehicles)", m_nNodes);
  cmd.AddValue("sinks", "Number of routing sinks", m_nSinks);
  cmd.AddValue("txp", "Transmit power (dB), e.g. txp=7.5", m_txp);
  cmd.AddValue("traceMobility", "Enable mobility tracing", m_traceMobility);
  cmd.AddValue("protocol", "1=OLSR;2=AODV;3=DSDV;4=DSR", m_protocol);
  cmd.AddValue("lossModel", "1=Friis;2=ItuR1411Los;3=TwoRayGround;4=LogDistance", m_lossModel);
  cmd.AddValue("fading", "0=None;1=Nakagami;(buildings=1 overrides)", m_fading);
  cmd.AddValue("phyMode", "Wifi Phy mode", m_phyMode);
  cmd.AddValue("80211Mode", "1=802.11p; 2=802.11b; 3=WAVE-PHY", m_80211mode);
  cmd.AddValue("traceFile", "Ns2 movement trace file", m_traceFile);
  cmd.AddValue("logFile", "Log file", m_logFile);
  cmd.AddValue("mobility", "1=trace;2=RWP", m_mobility);
  cmd.AddValue("rate", "Rate", m_rate);
  cmd.AddValue("phyModeB", "Phy mode 802.11b", m_phyModeB);
  cmd.AddValue("speed", "Node speed (m/s)", m_nodeSpeed);
  cmd.AddValue("pause", "Node pause (s)", m_nodePause);
  cmd.AddValue("verbose", "0=quiet;1=verbose", m_verbose);
  cmd.AddValue("gpsaccuracy", "GPS time accuracy, in ns", m_gpsAccuracyNs);
  cmd.AddValue("txmaxdelay", "Tx max delay, in ms", m_txMaxDelayMs);
  cmd.AddValue("routingTables", "Dump routing tables at t=5 seconds", m_routingTables);
  cmd.AddValue("asciiTrace", "Dump ASCII Trace data", m_asciiTrace);
  cmd.AddValue("pcap", "Create PCAP files for all nodes", m_pcap);
  cmd.AddValue("loadconfig", "Config-store filename to load", m_loadConfigFilename);
  cmd.AddValue("saveconfig", "Config-store filename to save", m_saveConfigFilename);
  cmd.AddValue("exp", "Experiment", m_exp);
  cmd.Parse(argc, argv);

  ConfigStoreHelper configStoreHelper;
  configStoreHelper.LoadConfig(m_loadConfigFilename);
  SetConfigFromGlobals();
  cmd.Parse(argc, argv);
}

void VanetRoutingExperiment::SetupLogFile()
{
  m_os.open(m_logFile.c_str());
}

void VanetRoutingExperiment::SetupLogging()
{
  LogComponentEnable("Ns2MobilityHelper", LOG_LEVEL_DEBUG);
  Packet::EnablePrinting();
}

void VanetRoutingExperiment::ConfigureDefaults()
{
  Config::SetDefault("ns3::OnOffApplication::PacketSize", StringValue("64"));
  Config::SetDefault("ns3::OnOffApplication::DataRate", StringValue(m_rate));

  if (m_80211mode == 2)
  {
    Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue(m_phyModeB));
  }
  else
  {
    Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue(m_phyMode));
  }
}

void VanetRoutingExperiment::SetupAdhocMobilityNodes()
{
  Ns2MobilityHelper ns2 = Ns2MobilityHelper(m_traceFile);
  ns2.Install();
}

// 수정 - 2

/*
void PrintMacAddresses(Ptr<const Packet> p)
{
  Ptr<Packet> nonConstP = p->Copy();
  EthernetHeader ethernetHeader;
  if (nonConstP->PeekHeader(ethernetHeader))
  {
    Mac48Address srcMacAddress = ethernetHeader.GetSource();
    Mac48Address destMacAddress = ethernetHeader.GetDestination();

    std::cout << "UID : " << nonConstP->GetUid()
              << " / 충돌 발생 시각 : " << Simulator::Now().GetNanoSeconds()
              << "s. Src MAC address: " << srcMacAddress
              << ", Dest MAC address: " << destMacAddress << std::endl;
  }
  else
  {
    std::cout << "Cannot extract EthernetHeader from packet" << std::endl;
  }
}


void PrintMacAddresses(Ptr<const Packet> p)
{
  Ptr<Packet> nonConstP = p->Copy();
  WifiMacHeader wifiMacHeader;

  if (nonConstP->RemoveHeader(wifiMacHeader))
  {
    Mac48Address srcMacAddress = wifiMacHeader.GetAddr2();
    Mac48Address destMacAddress = wifiMacHeader.GetAddr1();


    std::cout << "UID : " << nonConstP->GetUid()
              << " / 충돌 발생 시각 : " << Simulator::Now().GetNanoSeconds()
              << "s. Src MAC address: " << srcMacAddress
              << ", Dest MAC address: " << destMacAddress << std::endl;

  }
  else
  {
    std::cout << "Cannot extract WifiMacHeader from packet" << std::endl;
  }
}
*/


void PrintMacType(Ptr<const Packet> p)
{
  
}

void VanetRoutingExperiment::SetupAdhocDevices()
{
  m_lossModelName = "ns3::TwoRayGroundPropagationLossModel";
  double freq = 5.9e9;
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");

  wifiChannel.AddPropagationLoss(m_lossModelName, "Frequency", DoubleValue(freq), "HeightAboveZ", DoubleValue(1.5));

  if (m_fading != 0)
  {
    wifiChannel.AddPropagationLoss("ns3::NakagamiPropagationLossModel");
  }

  Ptr<YansWifiChannel> channel = wifiChannel.Create();

  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default();
  wifiPhy.SetChannel(channel);
  wifiPhy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11);

  YansWavePhyHelper wavePhy = YansWavePhyHelper::Default();
  wavePhy.SetChannel(channel);
  wavePhy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11);

  NqosWaveMacHelper wifi80211pMac = NqosWaveMacHelper::Default();
  WaveHelper waveHelper = WaveHelper::Default();
  Wifi80211pHelper wifi80211p = Wifi80211pHelper::Default();

  // wifi80211p.EnableLogComponents();

  if (m_verbose)
  {
    /*

    수정 - 3

    */

    wifi80211p.EnableLogComponents();
    m_adhocTxDevices = wifi80211p.Install(wifiPhy, wifi80211pMac, m_adhocTxNodes);

    for (uint32_t i = 0; i < m_adhocTxDevices.GetN(); i++)
    {
      Ptr<NetDevice> device = m_adhocTxDevices.Get(i);
      Ptr<WifiNetDevice> wifiDevice = DynamicCast<WifiNetDevice>(device);
      if (wifiDevice)
      {
        Ptr<WifiPhy> phy = wifiDevice->GetPhy();
        Ptr<YansWifiPhy> yansPhy = DynamicCast<YansWifiPhy>(phy);
        if (yansPhy)
        {
          // yansPhy->TraceConnectWithoutContext("PhyRxDrop", MakeCallback(&PrintMacAddresses));
          yansPhy->TraceConnectWithoutContext("PhyRxDrop", MakeCallback(&PrintMacType));
        }
      }
    }
  }

  WifiHelper wifi;

  uint32_t yourLongRetryLimit = 3; // tx access start
  uint32_t yourShortRetryLimit = 3;

  wifi.SetStandard(WIFI_PHY_STANDARD_80211b);

  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                               "DataMode", StringValue(m_phyModeB),
                               "ControlMode", StringValue(m_phyModeB),
                               "MaxSlrc", UintegerValue(yourLongRetryLimit),
                               "MaxSsrc", UintegerValue(yourShortRetryLimit));

  wifi80211p.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode", StringValue(m_phyMode),
                                     "ControlMode", StringValue(m_phyMode),
                                     "MaxSlrc", UintegerValue(yourLongRetryLimit),
                                     "MaxSsrc", UintegerValue(yourShortRetryLimit));

  waveHelper.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode", StringValue(m_phyMode),
                                     "ControlMode", StringValue(m_phyMode),
                                     "MaxSlrc", UintegerValue(yourLongRetryLimit),
                                     "MaxSsrc", UintegerValue(yourShortRetryLimit));

  wifiPhy.Set("TxPowerStart", DoubleValue(m_txp));
  wifiPhy.Set("TxPowerEnd", DoubleValue(m_txp));

  wavePhy.Set("TxPowerStart", DoubleValue(m_txp));
  wavePhy.Set("TxPowerEnd", DoubleValue(m_txp));

  WifiMacHelper wifiMac;
  wifiMac.SetType("ns3::AdhocWifiMac");
  QosWaveMacHelper waveMac = QosWaveMacHelper::Default();
  m_adhocTxDevices = wifi80211p.Install(wifiPhy, wifi80211pMac, m_adhocTxNodes);

  if (m_pcap != 0)
  {
    wifiPhy.EnablePcapAll("vanet-routing-compare-pcap");
    wavePhy.EnablePcapAll("vanet-routing-compare-pcap");
  }
}

void VanetRoutingExperiment::SetupRoutingMessages()
{
  m_routingHelper->Install(m_adhocTxNodes,
                           m_adhocTxDevices,
                           m_adhocTxInterfaces,
                           m_TotalSimTime,
                           m_protocol,
                           m_nSinks,
                           m_routingTables);
}

void VanetRoutingExperiment::SetupScenario()
{
  m_logFile = "vanet.log";
  m_mobility = 1;
  m_nNodes = 50;
  m_TotalSimTime = 300.01;
  m_nodeSpeed = 0;
  m_nodePause = 0;
  m_CSVfileName = "vanet.csv";
  m_CSVfileName = "vanet2.csv";
}

int main(int argc, char *argv[])
{
  time_t start, finish;
  double duration;

  start = time(NULL);
  VanetRoutingExperiment experiment;
  experiment.Simulate(argc, argv);

  finish = time(NULL);

  duration = (double)(finish - start);
  std::cout << duration << " Seconds" << '\n';
}
