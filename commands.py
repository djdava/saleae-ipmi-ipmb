"""Command identifiers, not payload decoders. Request NetFn is used as key.

Sources and coverage limitations are documented in README.md. Group Extension
commands MUST also be selected by their group ID, not just NetFn 0x2c.
"""


def _table(text):
    return {int(code, 16): name for code, name in
            (line.split(' ', 1) for line in text.strip().splitlines())}


STANDARD = {
    0x00: _table("""
00 Get Chassis Capabilities
01 Get Chassis Status
02 Chassis Control
03 Chassis Reset
04 Chassis Identify
05 Set Chassis Capabilities
06 Set Power Restore Policy
07 Get System Restart Cause
08 Set System Boot Options
09 Get System Boot Options
0a Set Front Panel Button Enables
0b Set Power Cycle Interval
0f Get POH Counter
"""),
    0x02: _table("""
00 Get Bridge State
01 Set Bridge State
02 Get ICMB Address
03 Set ICMB Address
04 Set Bridge Proxy Address
05 Get Bridge Statistics
06 Get ICMB Capabilities
08 Clear Bridge Statistics
09 Get Bridge Proxy Address
0a Get ICMB Connector Info
0b Get ICMB Connection ID
0c Send ICMB Connection ID
10 Prepare For Discovery
11 Get Addresses
12 Set Discovered
13 Get Chassis Device ID
14 Set Chassis Device ID
20 Bridge Request
21 Bridge Message
30 Get Event Count
31 Set Event Destination
32 Set Event Reception State
33 Send ICMB Event Message
34 Get Event Destination
35 Get Event Reception State
ff Error Report
"""),
    0x04: _table("""
00 Set Event Receiver
01 Get Event Receiver
02 Platform Event
10 Get PEF Capabilities
11 Arm PEF Postpone Timer
12 Set PEF Configuration Parameters
13 Get PEF Configuration Parameters
14 Set Last Processed Event ID
15 Get Last Processed Event ID
16 Alert Immediate
17 PET Acknowledge
20 Get Device SDR Info
21 Get Device SDR
22 Reserve Device SDR Repository
23 Get Sensor Reading Factors
24 Set Sensor Hysteresis
25 Get Sensor Hysteresis
26 Set Sensor Thresholds
27 Get Sensor Thresholds
28 Set Sensor Event Enable
29 Get Sensor Event Enable
2a Re-arm Sensor Events
2b Get Sensor Event Status
2d Get Sensor Reading
2e Set Sensor Type
2f Get Sensor Type
30 Set Sensor Reading and Event Status
"""),
    0x06: _table("""
01 Get Device ID
02 Cold Reset
03 Warm Reset
04 Get Self Test Results
05 Manufacturing Test On
06 Set ACPI Power State
07 Get ACPI Power State
08 Get Device GUID
09 Get NetFn Support
0a Get Command Support
0b Get Command Sub-function Support
0c Get Configurable Commands
0d Get Configurable Command Sub-functions
22 Reset Watchdog Timer
24 Set Watchdog Timer
25 Get Watchdog Timer
2e Set BMC Global Enables
2f Get BMC Global Enables
30 Clear Message Flags
31 Get Message Flags
32 Enable Message Channel Receive
33 Get Message
34 Send Message
35 Read Event Message Buffer
36 Get BT Interface Capabilities
37 Get System GUID
38 Get Channel Authentication Capabilities
39 Get Session Challenge
3a Activate Session
3b Set Session Privilege Level
3c Close Session
3d Get Session Info
3f Get AuthCode
40 Set Channel Access
41 Get Channel Access
42 Get Channel Info
43 Set User Access
44 Get User Access
45 Set User Name
46 Get User Name
47 Set User Password
48 Activate Payload
49 Deactivate Payload
4a Get Payload Activation Status
4b Get Payload Instance Info
4c Set User Payload Access
4d Get User Payload Access
4e Get Channel Payload Support
4f Get Channel Payload Version
50 Get Channel OEM Payload Info
52 Master Write-Read
54 Get Channel Cipher Suites
55 Suspend/Resume Payload Encryption
56 Set Channel Security Keys
57 Get System Interface Capabilities
58 Set System Info Parameters
59 Get System Info Parameters
60 Set Command Enables
61 Get Command Enables
62 Set Command Sub-function Enables
63 Get Command Sub-function Enables
64 Get OEM NetFn IANA Support
"""),
    0x0A: _table("""
10 Get FRU Inventory Area Info
11 Read FRU Data
12 Write FRU Data
20 Get SDR Repository Info
21 Get SDR Repository Allocation Info
22 Reserve SDR Repository
23 Get SDR
24 Add SDR
25 Partial Add SDR
26 Delete SDR
27 Clear SDR Repository
28 Get SDR Repository Time
29 Set SDR Repository Time
2a Enter SDR Repository Update Mode
2b Exit SDR Repository Update Mode
2c Run Initialization Agent
40 Get SEL Info
41 Get SEL Allocation Info
42 Reserve SEL
43 Get SEL Entry
44 Add SEL Entry
45 Partial Add SEL Entry
46 Delete SEL Entry
47 Clear SEL
48 Get SEL Time
49 Set SEL Time
5a Get Auxiliary Log Status
5b Set Auxiliary Log Status
5c Get SEL Time UTC Offset
5d Set SEL Time UTC Offset
"""),
    0x0C: _table("""
01 Set LAN Configuration Parameters
02 Get LAN Configuration Parameters
03 Suspend BMC ARPs
04 Get IP/UDP/RMCP Statistics
10 Set Serial/Modem Configuration
11 Get Serial/Modem Configuration
12 Set Serial/Modem Mux
13 Get TAP Response Codes
14 Set PPP UDP Proxy Transmit Data
15 Get PPP UDP Proxy Transmit Data
16 Send PPP UDP Proxy Packet
17 Get PPP UDP Proxy Receive Data
18 Serial/Modem Connection Active
19 Callback
1a Set User Callback Options
1b Get User Callback Options
1c Set Serial Routing Mux
20 SOL Activating
21 Set SOL Configuration Parameters
22 Get SOL Configuration Parameters
30 Forwarded Command
31 Set Forwarded Commands
32 Get Forwarded Commands
33 Enable Forwarded Commands
"""),
}

PICMG = _table("""
00 Get PICMG Properties
01 Get Address Info
02 Get Shelf Address Info
03 Set Shelf Address Info
04 FRU Control
05 Get FRU LED Properties
06 Get LED Color Capabilities
07 Set FRU LED State
08 Get FRU LED State
09 Set IPMB State
0a Set FRU Activation Policy
0b Get FRU Activation Policy
0c Set FRU Activation
0d Get Device Locator Record ID
0e Set Port State
0f Get Port State
10 Compute Power Properties
11 Set Power Level
12 Get Power Level
13 Renegotiate Power
14 Get Fan Speed Properties
15 Set Fan Level
16 Get Fan Level
17 Bused Resource Control
18 Get IPMB Link Info
19 Set AMC Port State
1a Get AMC Port State
1b Get Shelf Manager IPMB Address
1c Set Fan Policy
1d Get Fan Policy
1e FRU Control Capabilities
1f FRU Inventory Device Lock Control
20 FRU Inventory Device Write
21 Get Shelf Manager IP Addresses
22 Get Shelf Power Allocation
23 Get Location Information
24 Power Channel Control
25 Get Power Channel Status
26 PM Reset
27 Get PM Status
28 PM Heartbeat
29 Get Telco Alarm Capability
2a Set Telco Alarm State
2b Get Telco Alarm State
2c Set Clock State
2d Get Clock State
2e Get Target Upgrade Capabilities
2f Get Component Properties
30 Abort Firmware Upgrade
31 Initiate Upgrade Action
32 Upload Firmware Block
33 Finish Firmware Upload
34 Get Upgrade Status
35 Activate Firmware
36 Query Self-test Results
37 Query Rollback Status
38 Initiate Manual Rollback
3e Get HPM.x Capabilities
3f Get Dynamic Credentials
40 Get Session Handle for Explicit LAN Bridging
41 Get ATCA Extended Management Resources
42 Get AMC Extended Management Resources
43 Set ATCA Extended Management State
44 Get ATCA Extended Management State
45 Set AMC Power State
46 Get AMC Power State
47 Assign SOL Payload Instance
48 Get IP Address Source
""")

COMPLETION_CODES = _table("""
00 OK
c0 Node Busy
c1 Invalid Command
c2 Invalid Command for LUN
c3 Timeout
c4 Out of Space
c5 Reservation Canceled or Invalid
c6 Request Data Truncated
c7 Invalid Request Data Length
c8 Request Data Field Length Limit Exceeded
c9 Parameter Out of Range
ca Cannot Return Requested Data Bytes
cb Requested Sensor, Data or Record Not Present
cc Invalid Data Field in Request
cd Illegal Command for Sensor or Record Type
ce Response Unavailable
cf Duplicate Request
d0 SDR Repository in Update Mode
d1 Device in Firmware Update Mode
d2 BMC Initialization in Progress
d3 Destination Unavailable
d4 Insufficient Privilege
d5 Not Supported in Present State
d6 Subfunction Disabled or Unavailable
ff Unspecified Error
""")


def command_name(netfn, command, payload):
    """Return (name, catalogued). Never confuse PICMG with another group."""
    request_netfn = netfn & ~1
    if request_netfn == 0x2C:
        if not payload:
            return 'Group Extension (missing group ID), Cmd 0x%02X' % command, False
        if payload[0] == 0:
            name = PICMG.get(command)
            if name:
                return name, True
        return 'Group 0x%02X, Cmd 0x%02X' % (payload[0], command), False
    name = STANDARD.get(request_netfn, {}).get(command)
    if name:
        return name, True
    kind = 'OEM' if request_netfn == 0x2E or request_netfn >= 0x30 else 'Unknown'
    return '%s NetFn 0x%02X, Cmd 0x%02X' % (kind, request_netfn, command), False


def completion_name(code):
    if code in COMPLETION_CODES:
        return COMPLETION_CODES[code]
    if 0x01 <= code <= 0x7E:
        return 'OEM-specific completion'
    if 0x80 <= code <= 0xBE:
        return 'Command-specific completion'
    return 'Unknown completion'
