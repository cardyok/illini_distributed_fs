package main

import (
	"strconv"
	"fmt"
	"time"
	"bufio"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"strings"
	"flag"
	"reflect"
	"math/rand"
	"hash/fnv"
    "os/signal"
    "syscall"
    "encoding/gob"
    "log"
    "io"
)
type FileStruct struct{
	filename string
	timestamp int64
}
type MemberNode struct {
	ip string
	timestamp int64
	alive bool
}
type MonitorNode struct {
	conn *net.UDPConn
	ip string
	vid int
}

type ChildNode struct {
	timestamp int64
}

var introducer = "172.22.152.196"
var introducerPort = 8082
var introPingPeriod = 5

var myVid int
var otherPort = 8081
var myIP string

var fileList [10][]FileStruct
var bigList [10][]int
var memberMap = make(map[int]*MemberNode)
var monitors = make(map[string]*MonitorNode)
var children = make(map[int]*ChildNode)

var eventTimeMap = make(map[int]int64)
var fingerTable = make(map[int]int)
var fingerTablePeriod int64 = 10

var heartbeatPort = 8080
var heartbeatPeriod int64 = 1
var suspects []int 

var garbage = make(map[int]bool)

var maxID = 0
var delimiter = ","

var packetDropProb float64 = 0.0
var num_tries int = 3

func sendHeartbeat() {
	for {
		for _, node := range(monitors) {
			if rand.Float64() > packetDropProb {
				_, err := node.conn.Write([]byte(strconv.Itoa(myVid)))
				if err != nil {
					// log.Printf("[ME %d] Could not send heartbeat to %s %d", myVid, type_, node.vid)
				}
			} else {
				// log.Printf("[ME %d] Dropped the heartbeat to monitor=%d", myVid, node.vid)
			}
		}
		time.Sleep(time.Duration(heartbeatPeriod) * time.Second)
	}
}

func receiveHeartbeat() {
	var myaddr net.UDPAddr
	myaddr.IP = net.ParseIP(myIP)
	myaddr.Port = heartbeatPort

	heartbeatConn, err := net.ListenUDP("udp", &myaddr)
	if err != nil {
		// log.Printf("Unable to setup listen on the heartbeat port %d", heartbeatPort)
	}

	// log.Printf("Listening on heartbeat port %d", heartbeatPort)

	for {
		var buf [512]byte
		n, _, err := heartbeatConn.ReadFromUDP(buf[0:])
		if err != nil {
			// log.Printf("Could not read message on heartbeat port %d", heartbeatPort)
		}
		message := string(buf[0:n])
		child_vid, err := strconv.Atoi(message)
		if err != nil {
			// log.Printf("Could not map a heartbeat message %s to a virtual ID\n", message)
		}

		// Check if the sender vid is in your children map
		_, ok := children[child_vid]
		if ok {
			children[child_vid].timestamp = time.Now().Unix()
		} else{
			// log.Printf("Received a non-child heartbeat from vid=%d, ip=%s", child_vid, addr.IP.String())

		}
	}
}

func printMembershipList() {
	for id := range(memberMap) {
		fmt.Println(id,memberMap[id].alive," ",memberMap[id].ip)
	}
	for i,s := range(bigList) {
		fmt.Println(i,s)
	}
	for i,s := range(fileList) {
		fmt.Println(i,s)
	}
}

func printChildren() {
	child_list := []int{}
	for child_vid := range children {
		child_list = append(child_list, child_vid)
	}
	// log.Printf("[ME %d] Children = %v", myVid, child_list)
}

func checkChildren() {
	for {
		currTime := time.Now().Unix()

		for child_vid, cnode := range children {
			if currTime - cnode.timestamp > 2 * heartbeatPeriod {
				// log.Printf("[ME %d] No heartbeat from %d since two heartbeat periods", myVid, child_vid)
				suspects = append(suspects, child_vid)
				go checkSuspicion(child_vid)
			}
		}
		time.Sleep(time.Duration(heartbeatPeriod) * time.Second)
	}
	return
}

func checkSuspicion(vid int) {
	// To check suspicion, query its neighbors
	pred := getPredecessor(vid)
	succ1 := getSuccessor(vid)
	succ2 := getSuccessor2(vid)

	for _, nvid := range([]int{pred, succ1, succ2}) {
		if nvid == myVid {
			continue
		}

		// log.Printf("[ME %d] Raising suspicion for %d", myVid, vid)

		message := fmt.Sprintf("SUSPECT,%d", vid)
		sendMessage(nvid, message, num_tries)
	}

	// after 1 second, if the vid is still in suspects, declare it CRASHed
	time.Sleep(time.Duration(1) * time.Second) 

	suspect_idx := -1
	for i, suspect := range(suspects) {
		if suspect == vid {
			suspect_idx = i
			memberMap[suspect].alive = false
			_, ok := children[vid]
			if ok {
				delete(children, vid)
			}
			// log.Printf("[ME %d] Marked %d as crashed", myVid, suspect)
			crash_time := time.Now().Unix()
			message := fmt.Sprintf("CRASH,%d,%d", vid, crash_time)
			eventTimeMap[vid] = crash_time
			disseminate(message)
			updateMonitors()
			break
		}
	}

	// remove dead node from suspects
	if suspect_idx != -1 {
		suspects[suspect_idx] = suspects[len(suspects)-1]
		suspects = suspects[:len(suspects)-1]
	}
	return
}

func sendMessage(vid int, message string, num_tries int) {
	var addr net.UDPAddr
	addr.IP = net.ParseIP(memberMap[vid].ip)
	addr.Port = otherPort

	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		// log.Printf("[ME %d] Unable to dial UDP to vid=%d ip=%s", myVid, vid, memberMap[vid].ip)
	}
	defer conn.Close()
	for i:=0; i<num_tries; i++ {
		if rand.Float64() > packetDropProb {
			_, err = conn.Write([]byte(message))
			if err != nil {
				// log.Printf("[ME %d] Unable to write message %s on the connection to vid=%d", myVid, message, vid)
			}
		} else {
			// log.Printf("[ME %d] Dropped the message %s to vid=%d", myVid, message, vid)
		}	
	}
	return
}

func sendMessageAddr(ip string, message string, num_tries int) {
	var addr net.UDPAddr
	addr.IP = net.ParseIP(ip)
	addr.Port = otherPort

	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		// log.Printf("[ME %d] Unable to dial UDP to ip=%s", myVid, ip)
	}
	defer conn.Close()
	for i:=0; i<num_tries; i++ {
		if rand.Float64() > packetDropProb {
			_, err = conn.Write([]byte(message))
			if err != nil {
				// log.Printf("[ME %d] Unable to write message %s on the connection to ip=%s", myVid, message, ip)
			}
		} else {
			// log.Printf("[ME %d] Dropped the message %s to ip=%s", myVid, message, ip)
		}
	}
	return
}

// golang % operator can return negative values, define a positive mod function
func mod(a int, b int) int {
    m := a % b
    if a < 0 && b > 0 {
        m += b
    }
    return m
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
	
}

func getPredecessor(vid int) (int) {
	n := maxID + 1
	if n < 2 {
		return -1
	}

	pred := mod(vid - 1, n)
	attempts := 0
	for {
		_, ok := memberMap[pred]
		if ok && memberMap[pred].alive == true {
			if pred != vid {
				break
			}
		}
		pred = mod(pred - 1, n)
		attempts += 1
		if attempts > n {
			return -1
		}
	}
	return pred
}

func getSuccessor(vid int) (int) {
	n := maxID + 1
	if n < 2 {
		return -1
	}
	succ := (vid + 1) % n
	attempts := 0
	for {
		_, ok := memberMap[succ] // checking if succ is in the memberMap
		if ok && memberMap[succ].alive == true {
			if succ != vid {
				break
			}
		}
		succ = (succ + 1) % n
		attempts += 1
		if attempts > n {
			return -1
		}
	}
	return succ
}

func getSuccessor2(vid int) (int) {
	n := maxID + 1
	if n < 2 {
		return -1
	}

	succ1 := getSuccessor(vid)
	if succ1 == -1 {
		return -1
	}

	succ2 := (succ1 + 1) % n
	attempts := 0
	for {
		_, ok := memberMap[succ2]
		if ok && memberMap[succ2].alive == true {
			if succ2 != vid {
				break
			}
		}
		succ2 = (succ2 + 1) % n
		attempts += 1
		if attempts > n {
			return -1
		}
	}
	return succ2
}

func printFingerTable() {
	finger_list := []int{}
	for _, finger := range(fingerTable) {
		finger_list = append(finger_list, finger)
	}
	// log.Printf("[ME %d] Finger Table entries = %v", myVid, finger_list)
}

func updateFingerTable() {
	for {
		n := maxID + 1
		factor := 1
		idx := 0
		for {
			if (n < 2) {
				break
			}
			val := (myVid + factor) % n
			entry := getSuccessor(val)
			if (entry != myVid) {
				fingerTable[idx] = entry
				idx = idx + 1
			}
			factor = factor * 2
			if factor >= n {
				break
			}
		}

		stale_idx := len(fingerTable)
		for i:=idx; i<stale_idx; i++ {
			_, ok := fingerTable[i]
			if ok {
				delete(fingerTable, i)
			}
		}
		printFingerTable()
		time.Sleep(time.Duration(fingerTablePeriod) * time.Second)
	}
}

func disseminate(message string) {
	for _, node := range(monitors) {
		sendMessage(node.vid, message, 1)
	}
	for _, finger := range(fingerTable) {
		if (finger == myVid || memberMap[finger].alive == false) {
			continue
		}
		sendMessage(finger, message, 1)
	}
}


func checkIntroducer() {
	for {
		time.Sleep(time.Duration(introPingPeriod) * time.Second)
		if memberMap[0].alive == false {
			// If introducer is dead, periodically send your record to the introducer
			message := fmt.Sprintf("INTRODUCER,%d,%s,%d,%d",myVid,memberMap[myVid].ip,memberMap[myVid].timestamp,maxID)
			sendMessage(0, message, num_tries)
		}
	
	}
}

func findAndSendMonitors(vid int) {
	var pred, succ1, succ2 int

	pred = getPredecessor(vid)
	if pred != -1{
		message := fmt.Sprintf("PRED,%d,%s,%d", pred, memberMap[pred].ip, memberMap[pred].timestamp)
		sendMessage(vid, message, num_tries)
	}
	
	succ1 = getSuccessor(vid)
	if succ1 != -1 {
		message := fmt.Sprintf("SUCC1,%d,%s,%d", succ1, memberMap[succ1].ip, memberMap[succ1].timestamp)
		sendMessage(vid, message, num_tries)
	}
	
	succ2 = getSuccessor2(vid)
	if succ2 != -1 {
		message := fmt.Sprintf("SUCC2,%d,%s,%d", succ2, memberMap[succ2].ip, memberMap[succ2].timestamp)
		sendMessage(vid, message, num_tries)
	}
	
}

func completeJoinRequests() (err error) {

	var myaddr net.UDPAddr
	myaddr.IP = net.ParseIP(introducer)
	myaddr.Port = introducerPort

	introducerConn, err := net.ListenUDP("udp", &myaddr)
	if err != nil {
		// log.Printf("[ME %d] Unable to setup listen on the introducer port %d", myVid, introducerPort)
		return err
	}

	// log.Printf("[ME %d] Started listening on the introducer port %d", myVid, introducerPort)

	for {
		var buf [512]byte
		_, addr, err := introducerConn.ReadFromUDP(buf[0:])
		if err != nil {
			// log.Printf("[ME %d] Could not read message from the introducer port %d", myVid, introducerPort)
		}

		// log.Printf("[ME %d] Received a JOIN request from ip=%s", myVid, addr.IP.String())

		var newVid int

		if len(garbage) == 0 {
			maxID = maxID + 1
			newVid = maxID
		} else {
			for key := range(garbage) {
				newVid = key
				break
			}
			delete(garbage, newVid)
		}

		var newnode MemberNode
		newnode.ip = addr.IP.String()
		newnode.timestamp = time.Now().Unix()
		newnode.alive = true
		memberMap[newVid] = &newnode

		// log.Printf("[ME %d] Added entry ip=%s timestamp=%d at vid=%d", myVid, newnode.ip, newnode.timestamp, newVid)

		// Send the node's record
		message := fmt.Sprintf("YOU,%d,%s,%d", newVid, newnode.ip, newnode.timestamp)
		sendMessage(newVid, message, num_tries)

		// Send introducer record
		message = fmt.Sprintf("MEMBER,0,%s,%d", introducer, memberMap[0].timestamp)
		sendMessage(newVid, message, num_tries)

		findAndSendMonitors(newVid)
		
		// this delay is essential, otherwise it will be bombarded with MEMBER messages even before init setup
		time.Sleep(100 * time.Millisecond)

		message = fmt.Sprintf("JOIN,%d,%s,%d", newVid, newnode.ip, newnode.timestamp)
		eventTimeMap[newVid] = newnode.timestamp
		disseminate(message)

		updateMonitors()
	}
	return nil
}

func createMonitor(vid int) (MonitorNode) {
	var node MonitorNode
	node.vid = vid
	node.ip = memberMap[vid].ip

	var addr net.UDPAddr
	addr.IP = net.ParseIP(node.ip)
	addr.Port = heartbeatPort
	var err error
	node.conn, err = net.DialUDP("udp", nil, &addr)
	if err != nil {
		// log.Printf("[ME %d] Unable to setup a connection with monitor %d", myVid, vid)
	}
	return node
}

func createMember(ip string, str_timestamp string) (MemberNode){
	var node MemberNode
	node.ip = ip
	var err error
	node.timestamp, err = strconv.ParseInt(string(str_timestamp), 10, 64)
	if err != nil {
		// log.Printf("[ME %d] Cannot convert string timestamp to int64", myVid)
	}
	node.alive = true
	return node
}

// utility function for difference of lists - print when monitors updated
func Difference(a, b []int) (diff []int) {
	m := make(map[int]bool)

	for _, item := range b {
		m[item] = true
	}

    for _, item := range(a) {
    	_, ok := m[item]
    	if !ok {
    		diff = append(diff, item)
    	}
    }

    return
}

func updateMonitors() {

	old_monitors := []int{}
	new_monitors := []int{}

	_, ok := monitors["pred"]
	newpred := getPredecessor(myVid)

	if ok {
		old_monitors = append(old_monitors, monitors["pred"].vid)
		delete(monitors, "pred")
	}
	if newpred != -1 {
		monitor_node := createMonitor(newpred)
		monitors["pred"] = &monitor_node
		new_monitors = append(new_monitors, newpred)
	}

	_, ok = monitors["succ1"]
	newsucc1 := getSuccessor(myVid)

	if ok {
		old_monitors = append(old_monitors, monitors["succ1"].vid)
		delete(monitors, "succ1")
	}
	if newsucc1 != -1 {
		monitor_node := createMonitor(newsucc1)
		monitors["succ1"] = &monitor_node
		new_monitors = append(new_monitors, newsucc1)
	}

	_, ok = monitors["succ2"]
	newsucc2 := getSuccessor2(myVid)

	if ok {
		old_monitors = append(old_monitors, monitors["succ2"].vid)
		delete(monitors, "succ2")
	}
	if newsucc2 != -1 {
		monitor_node := createMonitor(newsucc2)
		monitors["succ2"] = &monitor_node
		new_monitors = append(new_monitors, newsucc2)
	}

	to_add := Difference(new_monitors, old_monitors)
	for _, vid := range(to_add) {
		message := fmt.Sprintf("ADD,%d,%s,%d", myVid, memberMap[myVid].ip, memberMap[myVid].timestamp)
		sendMessage(vid, message, num_tries)
	}

	to_remove := Difference(old_monitors, new_monitors)
	for _, vid := range(to_remove) {
		message := fmt.Sprintf("REMOVE,%d", myVid)
		sendMessage(vid, message, num_tries)
	}

	if !reflect.DeepEqual(old_monitors, new_monitors) {
		// log.Printf("[ME %d] Updated monitors from %v to %v", myVid, old_monitors, new_monitors)
	}
}

func printGarbage() {
	garbage_list := []int{}
	for k := range(garbage) {
		garbage_list = append(garbage_list, k)
	}
	// log.Printf("[ME %d] Garbage set = %v", myVid, garbage_list)
}


func garbageCollection() {
	for {
		time.Sleep(2 * time.Second)

		for i:=1; i<=maxID; i++ {
			mnode, isavailable := memberMap[i]
			if ((!isavailable || !mnode.alive) && (time.Now().Unix() - eventTimeMap[i] > 6)) {
				garbage[i] = true
			}
		}
		printGarbage()
	}
}


func listenOtherPort() (err error) {
	var myaddr net.UDPAddr
	myaddr.IP = net.ParseIP(myIP)
	myaddr.Port = otherPort

	otherportConn, err := net.ListenUDP("udp", &myaddr)
	// log.Printf("[ME %d] Started listening on the otherport %d", myVid, otherPort)

	if err != nil {
		// log.Printf("[ME %d] Unable to listen on the otherport port %d", myVid, otherPort)
		return err
	}

	for {
		var buf [512]byte
		n, addr, err := otherportConn.ReadFromUDP(buf[0:])
		if err != nil {
			// log.Printf("[ME %d] Could not read message on otherport %s", myVid, otherPort)
		}

		message := string(buf[0:n])
		split_message := strings.Split(message, delimiter)
		message_type := split_message[0]
		subject, _ := strconv.Atoi(split_message[1])
		maxID = max(maxID, subject)

		// log.Printf("[ME %d] Message = %s", myVid, message)

		switch message_type {
		case "ADD":
			var newnode MemberNode
			newnode = createMember(split_message[2], split_message[3])
			memberMap[subject] = &newnode

			var cnode ChildNode
			cnode.timestamp = time.Now().Unix()
			children[subject] = &cnode

			printChildren()

		case "REMOVE":
			_, ok := children[subject]
			if ok {
				delete(children, subject)
			}

			printChildren()

		case "INTRODUCER":
			if myVid == 0 {
				// Listen to atleast 4 different nodes than myself - to handle three simultaneous failures
				if len(memberMap) < 5 {
					newnode := createMember(split_message[2],split_message[3])
					memberMap[subject] = &newnode

					tempmax, _ := strconv.Atoi(split_message[4])
					maxID = max(maxID, tempmax)
					
					message := fmt.Sprintf("JOIN,%d,%s,%d", 0, memberMap[0].ip,memberMap[0].timestamp)
					updateMonitors()

					eventTimeMap[0] = memberMap[0].timestamp
					disseminate(message)

					// log.Printf("[ME %d] Processed introducer ping entry from vid=%d", myVid, subject)
				}
			}

		case "PRED", "SUCC1", "SUCC2":
			var newnode MemberNode
			newnode = createMember(split_message[2], split_message[3])
			memberMap[subject] = &newnode

			var node MonitorNode
			node = createMonitor(subject)
			monitors[strings.ToLower(message_type)] = &node

			old_mon, ok := monitors[strings.ToLower(message_type)]
			if ok {
				old_mon_vid := old_mon.vid
				if old_mon_vid != subject {
					message := fmt.Sprintf("REMOVE,%d", myVid)
					sendMessage(old_mon_vid, message, num_tries)
				}
			}

			message := fmt.Sprintf("ADD,%d,%s,%d", myVid, memberMap[myVid].ip, memberMap[myVid].timestamp)
			sendMessageAddr(newnode.ip, message, num_tries)

			// log.Printf("[ME %d] Set my %s to %d", myVid, strings.ToLower(message_type), subject)

		case "YOU":
			myVid = subject
			var newnode MemberNode
			newnode = createMember(split_message[2], split_message[3])
			memberMap[subject] = &newnode

			go checkIntroducer()

			// log.Printf("[ME %d] Processed my memberMap entry", myVid)

		case "MEMBER":
			if subject == myVid {
				break
			}
			newnode := createMember(split_message[2], split_message[3])
			memberMap[subject] = &newnode

			if subject != 0 {
				updateMonitors()
				// introducer is anyway going to send it monitors.
			}
			
			// log.Printf("[ME %d] Processed a new memberMap entry vid=%d", myVid, subject)

		case "JOIN":
			origin_time, _ := strconv.ParseInt(string(split_message[3]), 10, 64)

			_, ok := eventTimeMap[subject]
			if (!ok || eventTimeMap[subject] < origin_time) {
				eventTimeMap[subject] = origin_time
				disseminate(message)

				if subject != myVid {
					newnode := createMember(split_message[2], split_message[3])
					memberMap[subject] = &newnode
				}

				message := fmt.Sprintf("MEMBER,%d,%s,%d", myVid, myIP, memberMap[myVid].timestamp)
				sendMessage(subject, message, num_tries)

				updateMonitors()

				// log.Printf("[ME %d] Processed JOIN memberMap entry for vid=%d", myVid, subject)

				// printMembershipList()
			} 

		case "LEAVE", "CRASH":
			origin_time, _ := strconv.ParseInt(string(split_message[2]), 10, 64)

			_, ok := eventTimeMap[subject]
			if (!ok || eventTimeMap[subject] < origin_time){
				eventTimeMap[subject] = origin_time
				disseminate(message)

				_, ok := memberMap[subject]
				if ok {
					memberMap[subject].alive = false
					
					_, ok = children[subject]
					if ok {
						delete(children, subject)
					}

					if subject == maxID {
						var i int
						for i=maxID; i>=0; i-- {
							if memberMap[i].alive {
								break
							}
						}
						maxID = i						
					}

					updateMonitors()

					// log.Printf("[ME %d] Processed %s for %d, maxID = %d", myVid, message_type, subject, maxID)
				}
			}			

		case "SUSPECT":
			var alive = false

			// Checked if it is set as dead in my list, if yes send dead message already
			if memberMap[subject].alive == false {
				alive = false
			} else{
				var currTime = time.Now().Unix()
				for child_vid, cnode := range(children) {
					if subject == child_vid {
						if currTime - cnode.timestamp < heartbeatPeriod {
							alive = true
						}
						break
					}
				}
			}

			var message string
			if alive {
				message = fmt.Sprintf("STATUS,%d,1", subject)
			} else {
				message = fmt.Sprintf("STATUS,%d,0", subject)
			}
			sendMessageAddr(addr.IP.String(), message, num_tries)
			if alive {
				// log.Printf("[ME %d] Processed suspect message for %d, sent ALIVE", myVid, subject)
			} else {
				// log.Printf("[ME %d] Processed a suspect message for %d, sent NOT ALIVE", myVid, subject)
			}
		
		case "STATUS":
			status, _ := strconv.Atoi(split_message[2])
			if status == 1 {
				suspect_idx := -1
				for i, suspect := range(suspects) {
					if suspect == subject {
						suspect_idx = i
						break
					}
				}
				if suspect_idx != -1 {
					suspects[suspect_idx] = suspects[len(suspects)-1]
					suspects = suspects[:len(suspects)-1]
				}
			}
			if status == 1 {
				// log.Printf("[ME %d] Received ALIVE status for %d", myVid, subject)
			} else {
				// log.Printf("[ME %d] Received NOT ALIVE status for %d", myVid, subject)
			}
			
		}
	}
}

func sendJoinRequest() {
	var addr net.UDPAddr
	addr.IP = net.ParseIP(introducer)
	addr.Port = introducerPort

	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		// log.Printf("[ME %d] Unable to dial UDP to introducer ip=%s, port=%d", myVid, introducer, introducerPort)
	}
	message := "1"
	defer conn.Close()
	conn.Write([]byte(message))

	// log.Printf("[ME %d] Sent a JOIN request to introducer ip=%s", myVid, introducer)
	return
}

func getmyIP() (string) {
	var myip string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		// log.Fatalf("Cannot get my IP")
		os.Exit(1)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				myip = ipnet.IP.String()
			}
		}
	}
	return myip
}
	/************************************************* MP3 ******************************************************/

func hash(s string) uint32 {
        h := fnv.New32a()
        h.Write([]byte(s))
        return h.Sum32()
}
func findmin() int{
	min := -1
	for i := range(memberMap) {
		if memberMap[i].alive == true{
			if min < 0 {
				min = i
			} else if memberMap[i].ip<memberMap[min].ip {
				min = i
			}
		}
	}
	return min
}
func checkIfIamMaster() bool{
	min := findmin()
	myip := getmyIP()
	for a := range(memberMap) {
		if  myip == memberMap[a].ip{
			if min == a{
				return true
			}
			return false
		}
	}
	return false
}
func sendHelper(conn net.Conn, filename string) {
	file, _:= os.Open(filename)
	buf := make([]byte, 4096)
	fmt.Println("Start writting file:",filename)
	for {
		n, err := file.Read(buf)
		if err == io.EOF {
			fmt.Println("Finish Putting ",filename)
			file.Close()
			return
		}
		conn.Write(buf[:n])
		// fmt.Println("send a block",n)
	}
}

func receiveHelper(conn net.Conn, filename string) {
	buf := make([]byte, 4096)
	// fmt.Println(filename)
	file, _ := os.Create("recv/"+filename)
	for {
		n, err := conn.Read(buf)
		// fmt.Println(n,err)
		if err == io.EOF{
			fmt.Println("Finish Writting ",filename)
			conn.Close()
			file.Close()
			return
		}
		file.Write(buf[:n])
		// fmt.Println("finish write a block")
	}
}
func buildPutMrsp(hash int) []string{
	var ret []string
	// fmt.Println("get file hash ",hash)
	if len(bigList[hash])>0 {
		for i := 0; i<len(bigList[hash]); i++ {
			ret = append(ret,memberMap[bigList[hash][i]].ip)
		}
		return ret
	}
	// fmt.Println("no current assignment found")
	cnt := 0
	for i := 0; i< len(memberMap); i++{
		if memberMap[(i+hash)%len(memberMap)].alive == true {
			// fmt.Println((i+hash)%len(memberMap)," is alive")
			ret = append(ret,memberMap[(i+hash)%len(memberMap)].ip)
			bigList[hash] = append(bigList[hash],(i+hash)%len(memberMap))
			cnt = cnt + 1
			if cnt == 4{
				return ret
			}
		}
	}
	return ret
}

func delFile_M(dest string,filename string){
	conn, _ := net.Dial("tcp", dest)
	fmt.Fprintf(conn, "del_"+filename + "\n")
	conn.Close()
	return
}
func checkPresent(hash int, filename string) bool{
	for i := 0; i<len(fileList[hash]) ; i++ {
		if fileList[hash][i].filename == filename {
			if (time.Now().Unix() - fileList[hash][i].timestamp) < 60 {
				return true
			} else {
				os.Remove("recv/"+filename)
				fileList[hash] = append(fileList[hash][:i],fileList[hash][i+1:]...)
				return false
			}
		}
	}
	return false
}
func server() {
	l, err := net.Listen("tcp",":21000")
    if err != nil {
            fmt.Println(err)
            return
    }
    defer l.Close()
    for {
    		c, err := l.Accept()
		    if err != nil {
		            fmt.Println(err)
		            return
		    }
    	    message, _ := bufio.NewReader(c).ReadString('\n')
		    /* Command Syntax:
		    	0-3 : command
		    	4-24: filename
		    */
		    filename :=  message[4:5]
		    hash := int(hash(filename))//or filename string
		    hash = hash%len(memberMap)
		    // fmt.Println(message,len(message))
			switch message[:4]{
				case "upda"://update
					var ret []int
					for i:=0; i<len(fileList);i++ {
						if len(fileList[i])>0 {
							ret = append(ret,i)
						}
					}
					encoder := gob.NewEncoder(c)
					encoder.Encode(ret)
					c.Close()
				case "recM":
					c.Close()
					// fmt.Println(myVid,int(message[4])-60,int(message[5])-60,int(message[6])-60,int(message[7])-60)
					for i:= 5 ; i < 8; i++ {
						if int(message[i]) >= 60 {
							dest := memberMap[int(message[i])-60].ip
							for j := 0 ; j < len(fileList[int(message[4])-60]) ; j++ {
								go sendFile(dest,fileList[int(message[4])-60][j].filename,fileList[int(message[4])-60][j].filename,true)
							}
						}
					}
				case "put_":
					if checkPresent(hash,filename) == true{
						c.Write([]byte("NO\n"))
						c.Close()
					} else {
						fileList[hash] = append(fileList[hash],FileStruct{filename,time.Now().Unix()})
						l, _ := net.Listen("tcp",":21001")
						c.Write([]byte("ok\n"))
						c.Close()
						conn, _ := l.Accept()
						receiveHelper(conn,filename)
						l.Close()
					}
				case "putM":
					p := buildPutMrsp(hash)
					encoder := gob.NewEncoder(c)
					encoder.Encode(p)
					c.Close()
				case "get_":
					i:=0
					for i= 0 ; i < len(fileList[hash]);i++ {
						if fileList[hash][i].filename==filename{
							//TODO: send file back
							c.Close()
							src := int(message[5])-60
							dest := memberMap[src].ip+":21001"
							conn, _ := net.Dial("tcp", dest)
							sendHelper(conn,"recv/"+filename)
							conn.Close()
							break
						}
					}
					if i == len(fileList[hash]) {
						encoder := gob.NewEncoder(c)
						encoder.Encode("NO\n")
						c.Close()
					}
				case "getM":
					if len(bigList[hash])==0 {
						c.Write([]byte("NO\n"))
						// fmt.Print("NO\n")
					} else {
						c.Write([]byte(memberMap[bigList[hash][0]].ip+"\n"))
						// fmt.Println(memberMap[bigList[hash][0]].ip)
					}
					c.Close()
				case "ls_M":
					var ret []string
					for i:= 0 ; i < len(bigList[hash]);i++ {
						ret = append(ret, memberMap[bigList[hash][i]].ip)
					}
					encoder := gob.NewEncoder(c)
					encoder.Encode(ret)
					c.Close()
				case "del_":
					c.Close()
					i := 0
					for i = 0; i<len(fileList[hash]); i++ {
						if fileList[hash][i].filename == filename {
							fileList[hash] = append(fileList[hash][:i],fileList[hash][i+1:]...)
							//TODO: remove local file "filename"
							os.Remove("recv/"+filename)
							break
						}
					}
				case "delM":
					c.Close()
					for i:=0 ; i < len(bigList[hash]) ; i++ {
						if memberMap[bigList[hash][i]].alive == true{
							delFile_M(memberMap[bigList[hash][i]].ip+":21000",filename)
						}
					}
			}
    }
}
func updateBigList(){
	for i:= 0 ; i < len(memberMap);i++ {
		if memberMap[i].alive == true {
			dest := memberMap[i].ip+":21000"
			conn, _ := net.Dial("tcp", dest)
			fmt.Fprintf(conn, "update\n")
			dec := gob.NewDecoder(conn)
			var p []int
			dec.Decode(&p)
			for _,id := range(p) {
				bigList[id] = append(bigList[id],i)
				// fmt.Println(id)
			}
			conn.Close()
		}
	}
}
func checkInList(hash int, idx int) bool{
	// fmt.Println(hash,idx)
	if memberMap[idx].alive==false {
			return false
	}
	for i := 0 ; i < len(bigList[hash]);i++{
		if bigList[hash][i] == idx {
			return false
		} 
	}
	return true
}
func master(){
	var localList [10]bool
	var updateList bool
	for i:=0;i<10;i++ {
		localList[i] = false
	}

	masterBool := checkIfIamMaster()
	if masterBool == true {
		fmt.Println("start master service")
		if len(memberMap) > 1 { 
			updateBigList()
		}
	}
	for{
		updateList = false
		if masterBool != checkIfIamMaster(){
			fmt.Println("I am new master")
			masterBool = checkIfIamMaster()
			if masterBool == true {
				updateBigList()
				for i:=0;i<10;i++ {
					localList[i] = false
				}
			} else {
				for i := 0 ; i < 10; i++{
					bigList[i] = nil
				}
			}
		}

		if masterBool == true {
			for i := range (memberMap) {
				if memberMap[i].alive == true {
					localList[i] = true
				} else if localList[i] == true {
					localList[i] = false
					updateList = true
				}
			}
		}
		if updateList == true {
			var str string
			idx := -1
			cnt := 0
			//1. for each hash value, figure out next set of ip addresses
			for i := 0 ; i < 10; i++{
				str = "recM"
				cnt = 0
				idx = -1
				str += string(i+60)

				for j := 0 ; j<len(bigList[i]);j++{
					if memberMap[bigList[i][j]].alive == false {
						bigList[i] = append(bigList[i][:j],bigList[i][j+1:]...)
						j--
						cnt += 1
					} else if idx < 0 {
						idx = bigList[i][j]
					}
				}
				if cnt == 0 {
					continue
				}
				// fmt.Println("b")
				for j := len(memberMap)-1 ; j >=0; j--{
					if checkInList(i,j) == true {
						cnt -= 1
						str += string(j+60)
						bigList[i] = append(bigList[i],j)
						if cnt <= 0 {
							break
						}
					}
				}
				for j := len(str) ; j < 8 ; j ++ {
					str += string(59)
				}
				fmt.Print(idx,str," ")
				dest := memberMap[idx].ip+":21000"
				fmt.Println(dest)
				conn, err := net.Dial("tcp", dest)
				if err != nil {
					fmt.Print(err)
				}
				fmt.Fprintf(conn, str)
				conn.Close()

			}
			//2. update local bigList to update the new ip address
			//3. send to some alive node and copy file to them
		}
		time.Sleep(1 * time.Second)
	}

}
func sendFile(p string, local string, sdf string,iscopy bool){
	dest := p+":21000"
	// fmt.Println(dest)
	conn, _ := net.Dial("tcp", dest)
	fmt.Fprintf(conn, "put_"+sdf+"\n")
	message, _ := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if message[:2]=="NO"{
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Do you really want to change this recently updated file? ")
		reader.ReadString('\n')
		return
	}
	dest = p+":21001"
	conn, _ = net.Dial("tcp", dest)
	if iscopy == false {
		sendHelper(conn,"send/"+local)
	} else {
		sendHelper(conn,"recv/"+local)
	}

	conn.Close()
}
func putFile(dest string,local string,sdf string){
	conn, _ := net.Dial("tcp", dest)
	fmt.Fprintf(conn, "putM"+sdf + "\n")
	// listen for reply
	dec := gob.NewDecoder(conn)
	var p []string
	dec.Decode(&p)
	// fmt.Println(p)
	conn.Close()
	for i:= 0 ; i < len(p); i++{
		go sendFile(p[i],local,sdf,false)
	}
	return
}
func getFile(dest string,sdf string,local string){
	conn, _ := net.Dial("tcp", dest)
	fmt.Fprintf(conn, "getM"+sdf + "\n")
	// listen for reply
	p, _ := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	// fmt.Println(p,len(p))
	if p[:2] == "NO"{
		fmt.Println("No such file in file system")
		return	
	}
	dest = p[:14]+":21000"
	// fmt.Println(dest)
	conn, _ = net.Dial("tcp", dest)
	fmt.Fprintf(conn, "get_"+sdf + string(60+myVid)+"\n")
	conn.Close()
	l, _ := net.Listen("tcp",":21001")
	conn, _ = l.Accept()
	receiveHelper(conn,local)
	l.Close()
	return
}
func delFile(dest string,filename string){
	conn, _ := net.Dial("tcp", dest)
	fmt.Fprintf(conn, "delM"+filename + "\n")
	return
}
func lsFile(dest string,filename string){
	conn, _ := net.Dial("tcp", dest)
	fmt.Fprintf(conn, "ls_M"+filename + "\n")
	// listen for reply
	dec := gob.NewDecoder(conn)
	var p []string
	dec.Decode(&p)
	fmt.Println(p)
	conn.Close()
	return
}
func client(){
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan(){
		text := strings.Split(scanner.Text(), " ")
    	if text[0] == "p" {
        	printMembershipList()
    	} else if text[0] == "put" {//put filename
        	putFile(memberMap[findmin()].ip+":21000",text[1],text[2])
        	log.Printf("[ME] %s is stored on cloud as %s", text[1],text[2])
    	} else if text[0] == "get" {//get file
    		getFile(memberMap[findmin()].ip+":21000",text[1],text[2])
    	} else if text[0] == "delete" {
    		delFile(memberMap[findmin()].ip+":21000",text[1])
        	log.Printf("[ME] %s is removed from cloud", text[1])
    	} else if text[0] == "ls" {
    		lsFile(memberMap[findmin()].ip+":21000",text[1])
    	} else if text[0] == "store" {
    		for i:=0; i<len(fileList);i++{
    			for j:=0; j<len(fileList[i]);j++{
	    			fmt.Print(fileList[i][j].filename)
	    		}
    		}
    	}
	}
}
func deleteAll() {
 files, _ := ioutil.ReadDir("recv/")
 for _, f := range files {
  os.Remove("recv/"+f.Name())
 }
}

func main() {
	deleteAll()
	logFile := flag.String("logfile", "", "path to the log file")
	flag.Parse()

	var wg sync.WaitGroup
	wg.Add(1)



	f, err := os.Create(*logFile)
	if err != nil {
		log.Fatalf("Error opening the log file: %v", err)
	}
	defer f.Close()
	// mw := io.MultiWriter(os.Stdout, f)
	mw := f
	log.SetOutput(mw)

	myIP = getmyIP()
	fmt.Printf("%s", myIP)

	if myIP == introducer {
		myVid = 0
		var node MemberNode
		node.ip = myIP
		node.timestamp = time.Now().Unix()
		node.alive = true
		memberMap[0] = &node
	}

	go sendHeartbeat()
	go receiveHeartbeat()
	go checkChildren()

	go listenOtherPort()

	time.Sleep(time.Duration(introPingPeriod) * time.Second)
	
	if myIP == introducer {
		// there should be a delay here - depending on how frequently the introducer is being pinged
		// if the system already exists in some form, the introducer shouldn't accept join requests until it knows what the maxID is 
		go completeJoinRequests()
		go garbageCollection()
		// this garbage collection can occur concurrent to the addToDead list

	} else{
		sendJoinRequest()
	}
	go updateFingerTable()

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGQUIT)
	go func() {
		sig := <-sigs
		switch sig {
		case syscall.SIGQUIT:
			leave_time := time.Now().Unix()
			message := fmt.Sprintf("LEAVE,%d,%d", myVid, leave_time)
			disseminate(message)
			
			wg.Done()
		}
	}()

	/********************* MP3 ******************/
	//server
	fmt.Println("started server")
	go server()
	//client
	fmt.Println("started client")
    go client()

    go master()

	/********************* MP3 ******************/

	wg.Wait()
	return
}

