from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub
import csv
import time
import statistics
from datetime import datetime
from ml import MachineLearningAlgo
import os

# ======================
# CONFIGURACIÓN GLOBAL
# ======================
APP_TYPE = 1  # 1: DDoS detection
PREVENTION = 1  # Prevención activada
INTERVAL = 5  # Intervalo de monitoreo (segundos)
MIN_ATTACK_DURATION = 10  # Segundos mínimos para considerar ataque
CONSECUTIVE_DETECTIONS = 2  # Detecciones positivas requeridas
LOG_DIR = "/tmp/ddos_detection_logs"
DETECTION_LOG_FILE = os.path.join(LOG_DIR, "detection_events.log")
METRICS_LOG_FILE = os.path.join(LOG_DIR, "metrics_monitoring.log")

# ======================
# ESTRUCTURAS DE DATOS
# ======================
gflows = {}
iteration = {}
old_ssip_len = {}
prev_flow_count = {}
flow_cookie = {}
BLOCKED_PORTS = {}
keystore = {}
attack_start_time = {}

# Estructura para métricas de monitoreo
MONITOR_STATS = {
    'total_events': 0,
    'processed_events': 0,
    'start_time': time.time(),
    'last_report': time.time()
}

# ======================
# FUNCIONES AUXILIARES
# ======================
def get_iteration(dpid):
    global iteration
    iteration.setdefault(dpid, 0)
    return iteration[dpid]

def set_iteration(dpid, count):
    global iteration
    iteration[dpid] = count

def get_old_ssip_len(dpid):
    global old_ssip_len
    old_ssip_len.setdefault(dpid, 0)
    return old_ssip_len[dpid]

def set_old_ssip_len(dpid, count):
    global old_ssip_len
    old_ssip_len[dpid] = count

def get_prev_flow_count(dpid):
    global prev_flow_count
    prev_flow_count.setdefault(dpid, 0)
    return prev_flow_count[dpid]

def set_prev_flow_count(dpid, count):
    global prev_flow_count
    prev_flow_count[dpid] = count

def get_flow_number(dpid):
    global flow_cookie
    flow_cookie.setdefault(dpid, 0)
    flow_cookie[dpid] += 1
    return flow_cookie[dpid]

def calculate_value(key, val):
    key = str(key).replace(".", "_")
    if key in keystore:
        oldval = keystore[key]
        cval = (val - oldval) 
        keystore[key] = val
        return cval
    else:
        keystore[key] = val
        return 0

# ======================
# FUNCIONES DE LOGGING
# ======================
def init_logging():
    """Inicializa los archivos de log para la prueba"""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    
    with open(DETECTION_LOG_FILE, 'w') as f:
        f.write("timestamp|event_type|dpid|details\n")
    
    with open(METRICS_LOG_FILE, 'w') as f:
        f.write("timestamp|dpid|sfe|ssip|rfip|sdfp|sdfb|result\n")

def log_detection_event(event_type, dpid, details=None):
    """Registra un evento de detección en el log"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"{timestamp}|{event_type}|{dpid}|{details or ''}\n"
    
    with open(DETECTION_LOG_FILE, 'a') as f:
        f.write(log_entry)

def log_metrics(dpid, sfe, ssip, rfip, sdfp, sdfb, result):
    """Registra métricas de monitoreo en el log"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = (f"{timestamp}|{dpid}|{sfe}|{ssip}|{rfip}|"
                f"{sdfp}|{sdfb}|{result}\n")
    
    with open(METRICS_LOG_FILE, 'a') as f:
        f.write(log_entry)

# Inicializar logging al importar el módulo
init_logging()

# ======================
# CLASE PRINCIPAL
# ======================
class DDoSML(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSML, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_ip_to_port = {}
        self.datapaths = {}
        self.mitigation = 0
        self.mlobj = None
        self.attack_status = {}
        
        if APP_TYPE == 1:
            self.mlobj = MachineLearningAlgo()
            self.logger.info("Modo de detección DDoS (ML) activado")
        else:
            self.logger.info("Modo de colección de datos activado")
        
        self.flow_thread = hub.spawn(self._flow_monitor)

    # ======================
    # MONITOREO PRINCIPAL
    # ======================
    def _flow_monitor(self):
        hub.sleep(INTERVAL * 2)
        while True:
            current_time = time.time()
            # Reporte periódico
            if current_time - MONITOR_STATS['last_report'] >= 30:
                elapsed = current_time - MONITOR_STATS['start_time']
                rate = (MONITOR_STATS['processed_events'] / max(1, MONITOR_STATS['total_events'])) * 100
                self.logger.info(
                    f"*** Monitor Rate: {rate:.2f}% | "
                    f"Processed: {MONITOR_STATS['processed_events']} | "
                    f"Total: {MONITOR_STATS['total_events']} | "
                    f"Elapsed: {elapsed:.1f}s"
                )
                MONITOR_STATS['last_report'] = current_time
                
            for dp in self.datapaths.values():
                self.request_flow_metrics(dp)
            hub.sleep(INTERVAL)

    # ======================
    # MANEJADORES DE EVENTOS
    # ======================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        MONITOR_STATS['total_events'] += 1
        try:
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            dpid = datapath.id
            
            self.datapaths[dpid] = datapath
            self.mac_to_port.setdefault(dpid, {})
            self.arp_ip_to_port.setdefault(dpid, {})
            BLOCKED_PORTS.setdefault(dpid, [])
            self.attack_status.setdefault(dpid, {
                'active': False, 
                'start_time': 0,
                'positive_count': 0,
                'last_detection_time': 0
            })

            # Flujo por defecto (table-miss)
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]
            instructions = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )]
            self.add_flow(
                datapath=datapath,
                priority=0,
                match=match,
                instructions=instructions,
                serial_no=get_flow_number(dpid)
            )
            
            # Flujo para ARP
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
            self.add_flow(
                datapath=datapath,
                priority=10,
                match=match,
                instructions=instructions,
                serial_no=get_flow_number(dpid)
            )
            
            MONITOR_STATS['processed_events'] += 1
        except Exception as e:
            self.logger.error(f"Error en switch_features: {str(e)}")
            log_detection_event("ERROR", 0, f"switch_features:{str(e)}")

    def request_flow_metrics(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # ======================
    # MÉTRICAS DE DETECCIÓN
    # ======================
    def _speed_of_flow_entries(self, dpid, flows):
        curr_flow_count = len(flows)
        sfe = curr_flow_count - get_prev_flow_count(dpid)
        set_prev_flow_count(dpid, curr_flow_count)
        return sfe

    def _speed_of_source_ip(self, dpid, flows):
        ssip = set()
        for flow in flows:
            if 'ipv4_src' in flow.match:
                ssip.add(flow.match['ipv4_src'])
        
        cur_ssip_len = len(ssip)
        ssip_result = cur_ssip_len - get_old_ssip_len(dpid)
        set_old_ssip_len(dpid, cur_ssip_len)
        return ssip_result

    def _ratio_of_flowpair(self, dpid, flows):
        flow_count = max(len(flows) - 1, 1)
        interactive_flows = set()
        
        for flow in flows:
            if 'ipv4_src' in flow.match and 'ipv4_dst' in flow.match:
                src_ip = flow.match['ipv4_src']
                dst_ip = flow.match['ipv4_dst']
                flow_pair = frozenset({src_ip, dst_ip})
                interactive_flows.add(flow_pair)
        
        iflow = len(interactive_flows) * 2
        return float(iflow) / flow_count if flow_count > 0 else 1.0

    def _stddev_packets(self, dpid, flows):
        packet_counts = []
        byte_counts = []
        hdr = f"switch_{dpid}"
        
        for flow in flows:
            if 'ipv4_src' in flow.match and 'ipv4_dst' in flow.match:
                src_ip = flow.match['ipv4_src']
                dst_ip = flow.match['ipv4_dst']
                
                byte_key = f"{hdr}_{src_ip}_{dst_ip}.bytes_count"
                pkt_key = f"{hdr}_{src_ip}_{dst_ip}.packets_count"
                
                byte_diff = calculate_value(byte_key, flow.byte_count)
                pkt_diff = calculate_value(pkt_key, flow.packet_count)
                
                byte_counts.append(byte_diff)
                packet_counts.append(pkt_diff)
        
        try:
            stddev_pkt = statistics.stdev(packet_counts) if packet_counts else 0
            stddev_byte = statistics.stdev(byte_counts) if byte_counts else 0
            return stddev_pkt, stddev_byte
        except:
            return 0, 0

    # ======================
    # DETECCIÓN DE ATAQUES
    # ======================
    def _is_real_attack(self, dpid, result):
        status = self.attack_status[dpid]
        current_time = time.time()
        
        if '1' in result:
            log_detection_event("ATTACK_SIGNAL", dpid, f"count:{status['positive_count']+1}")
            status['positive_count'] += 1
            status['last_detection_time'] = current_time
            
            if not status['active']:
                status['start_time'] = current_time
                status['active'] = True
                ATTACK_START_TIMES[dpid] = current_time
                log_detection_event("ATTACK_STARTED", dpid, "evaluating")
                self.logger.info(f"Switch {dpid}: Posible ataque iniciado - En evaluación...")
                return False
        else:
            if current_time - status['last_detection_time'] > INTERVAL * 2:
                status['positive_count'] = max(0, status['positive_count'] - 1)
        
        duration = current_time - status['start_time']
        if (duration >= MIN_ATTACK_DURATION and 
            status['positive_count'] >= CONSECUTIVE_DETECTIONS):
            detection_time = current_time - ATTACK_START_TIMES.get(dpid, current_time)
            log_detection_event("ATTACK_DETECTED", dpid, f"detection_time:{detection_time:.2f}")
            self.logger.info(f"Switch {dpid}: Tiempo de detección: {detection_time:.2f}s")
            return True
        
        return False

    def _reset_attack_status(self, dpid):
        log_detection_event("ATTACK_RESET", dpid, "")
        self.attack_status[dpid] = {
            'active': False,
            'start_time': 0,
            'positive_count': 0,
            'last_detection_time': 0
        }

    # ======================
    # MANEJADOR DE ESTADÍSTICAS
    # ======================
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        MONITOR_STATS['total_events'] += 1
        try:
            dpid = ev.msg.datapath.id
            flows = ev.msg.body
            
            gflows.setdefault(dpid, [])
            gflows[dpid].extend(flows)

            if ev.msg.flags == 0:
                sfe = self._speed_of_flow_entries(dpid, gflows[dpid])
                ssip = self._speed_of_source_ip(dpid, gflows[dpid])
                rfip = self._ratio_of_flowpair(dpid, gflows[dpid])
                sdfp, sdfb = self._stddev_packets(dpid, gflows[dpid])

                if APP_TYPE == 1 and get_iteration(dpid) == 1:
                    self.logger.info(f"Switch {dpid} - sfe:{sfe} ssip:{ssip} rfip:{rfip} sdfp:{sdfp} sdfb:{sdfb}")
                    result = self.mlobj.classify([sfe, ssip, rfip, sdfp, sdfb])
                    log_metrics(dpid, sfe, ssip, rfip, sdfp, sdfb, result[0])
                    
                    if '1' in result:
                        if self._is_real_attack(dpid, result):
                            self.logger.warning(f"¡Ataque DDoS confirmado en Switch {dpid}!")
                            log_detection_event("ATTACK_CONFIRMED", dpid, f"mitigation:{PREVENTION}")
                            self.mitigation = 1
                            if PREVENTION == 1:
                                self._activate_prevention(dpid)
                        else:
                            self.logger.info(f"Switch {dpid}: Señales de ataque en progreso...")
                    else:
                        self.logger.info(f"Switch {dpid}: Tráfico normal")
                        if self.mitigation == 1:
                            self._deactivate_prevention(dpid)
                            self.mitigation = 0
                            log_detection_event("ATTACK_ENDED", dpid, "mitigation_disabled")
                        self._reset_attack_status(dpid)

            gflows[dpid] = []
            set_iteration(dpid, 1)
            MONITOR_STATS['processed_events'] += 1
            
        except Exception as e:
            self.logger.error(f"Error en flow_stats: {str(e)}")
            log_detection_event("ERROR", dpid, f"flow_stats:{str(e)}")

    # ======================
    # MECANISMOS DE PREVENCIÓN
    # ======================
    def _activate_prevention(self, dpid):
        datapath = self.datapaths.get(dpid)
        if not datapath:
            return
            
        self.logger.info(f"Iniciando prevención en Switch {dpid}")
        log_detection_event("PREVENTION_START", dpid, "")
        
        # 1. Bloquear puertos sospechosos
        suspicious_ports = self._identify_suspicious_ports(dpid)
        
        for port in suspicious_ports:
            if port not in BLOCKED_PORTS[dpid]:
                self.block_port(datapath, port)
                BLOCKED_PORTS[dpid].append(port)
                log_detection_event("PORT_BLOCKED", dpid, f"port:{port}")
                self.logger.info(f"Switch {dpid}: Puerto {port} bloqueado")
        
        # 2. Limitar tasa de flujos nuevos
        self._limit_new_flows(datapath)

    def _deactivate_prevention(self, dpid):
        datapath = self.datapaths.get(dpid)
        if not datapath:
            return
            
        self.logger.info(f"Finalizando prevención en Switch {dpid}")
        log_detection_event("PREVENTION_END", dpid, "")
        
        # 1. Limpiar flujos de bloqueo
        for port in BLOCKED_PORTS[dpid]:
            self._remove_block_flow(datapath, port)
            log_detection_event("PORT_UNBLOCKED", dpid, f"port:{port}")
        
        # 2. Restaurar límites normales
        self._restore_normal_flow_limits(datapath)
        
        BLOCKED_PORTS[dpid] = []
        self.logger.info(f"Switch {dpid}: Prevención desactivada")

    def _identify_suspicious_ports(self, dpid):
        suspicious_ports = set()
        
        for port, ip_list in self.arp_ip_to_port.get(dpid, {}).items():
            if len(ip_list) > 10:
                suspicious_ports.add(port)
        
        if dpid in gflows and gflows[dpid]:
            port_flow_counts = {}
            for flow in gflows[dpid]:
                if 'in_port' in flow.match:
                    port = flow.match['in_port']
                    port_flow_counts[port] = port_flow_counts.get(port, 0) + 1
            
            avg_flows = sum(port_flow_counts.values()) / len(port_flow_counts) if port_flow_counts else 0
            for port, count in port_flow_counts.items():
                if count > avg_flows * 3:
                    suspicious_ports.add(port)
        
        return list(suspicious_ports)

    def _limit_new_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # 1. Configurar medidor para limitar tráfico
        meter_id = 1
        bands = [parser.OFPMeterBandDrop(rate=100, burst_size=10)]
        meter_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands
        )
        datapath.send_msg(meter_mod)
        
        # 2. Crear flujo que aplica el medidor
        match = parser.OFPMatch()
        instructions = [
            parser.OFPInstructionMeter(meter_id),
            parser.OFPInstructionGotoTable(1)
        ]
        
        self.add_flow(
            datapath=datapath,
            priority=10,
            match=match,
            instructions=instructions,
            serial_no=get_flow_number(datapath.id),
            table_id=0
        )

    def _restore_normal_flow_limits(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Eliminar medidor
        meter_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_DELETE,
            meter_id=1
        )
        datapath.send_msg(meter_mod)

    def _remove_block_flow(self, datapath, portnumber):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=portnumber)
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match,
            priority=100
        )
        datapath.send_msg(mod)

    # ======================
    # MANEJO DE FLUJOS
    # ======================
    def add_flow(self, datapath, priority, match, instructions=None, serial_no=0, 
                buffer_id=None, idle_timeout=0, hard_timeout=0, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if instructions is None:
            instructions = []
        
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                table_id=table_id,
                cookie=serial_no,
                buffer_id=buffer_id,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                priority=priority,
                match=match,
                instructions=instructions
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                table_id=table_id,
                cookie=serial_no,
                priority=priority,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                match=match,
                instructions=instructions
            )
                
        datapath.send_msg(mod)

    def block_port(self, datapath, portnumber):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=portnumber)
        instructions = []  # No acciones = bloquear tráfico
        flow_serial_no = get_flow_number(datapath.id)
        self.add_flow(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=instructions,
            serial_no=flow_serial_no,
            hard_timeout=300
        )

    # ======================
    # MANEJADOR DE PAQUETES
    # ======================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        MONITOR_STATS['total_events'] += 1
        try:
            if ev.msg.msg_len < ev.msg.total_len:
                self.logger.debug("paquete truncado: %s de %s bytes",
                                ev.msg.msg_len, ev.msg.total_len)

            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']
            dpid = datapath.id

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)
            
            if not eth:
                return

            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return

            dst = eth.dst
            src = eth.src

            self.mac_to_port.setdefault(dpid, {})
            self.arp_ip_to_port.setdefault(dpid, {})
            self.arp_ip_to_port[dpid].setdefault(in_port, [])
            BLOCKED_PORTS.setdefault(dpid, [])

            self.mac_to_port[dpid][src] = in_port

            out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                arp_pkt = pkt.get_protocol(arp.arp)
                if arp_pkt and arp_pkt.src_ip not in self.arp_ip_to_port[dpid][in_port]:
                    self.arp_ip_to_port[dpid][in_port].append(arp_pkt.src_ip)

            if out_port != ofproto.OFPP_FLOOD:
                if eth.ethertype == ether_types.ETH_TYPE_IP:
                    ip_pkt = pkt.get_protocol(ipv4.ipv4)
                    if ip_pkt:
                        if self.mitigation and PREVENTION:
                            if (in_port not in BLOCKED_PORTS[dpid] and 
                                ip_pkt.src not in self.arp_ip_to_port[dpid].get(in_port, [])):
                                self.logger.warning(f"Bloqueando tráfico sospechoso desde {ip_pkt.src} en puerto {in_port}")
                                log_detection_event("TRAFFIC_BLOCKED", dpid, f"src:{ip_pkt.src},port:{in_port}")
                                self.block_port(datapath, in_port)
                                BLOCKED_PORTS[dpid].append(in_port)
                                return

                        match = parser.OFPMatch(
                            in_port=in_port,
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=ip_pkt.src,
                            ipv4_dst=ip_pkt.dst)
                        
                        actions = [parser.OFPActionOutput(out_port)]
                        instructions = [parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            actions
                        )]
                        flow_serial_no = get_flow_number(dpid)
                        
                        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                            self.add_flow(
                                datapath=datapath,
                                priority=1,
                                match=match,
                                instructions=instructions,
                                serial_no=flow_serial_no,
                                buffer_id=msg.buffer_id
                            )
                            return
                        else:
                            self.add_flow(
                                datapath=datapath,
                                priority=1,
                                match=match,
                                instructions=instructions,
                                serial_no=flow_serial_no
                            )

            actions = [parser.OFPActionOutput(out_port)]
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data
            )
            datapath.send_msg(out)
            MONITOR_STATS['processed_events'] += 1
            
        except Exception as e:
            self.logger.error(f"Error en packet_in: {str(e)}")
            log_detection_event("ERROR", 0, f"packet_in:{str(e)}")

if __name__ == '__main__':
    from ryu.cmd import manager
    import atexit
    
    # Registrar función para generar reporte al finalizar
    atexit.register(lambda: print("\nLogs de detección disponibles en:", LOG_DIR))
    manager.main()