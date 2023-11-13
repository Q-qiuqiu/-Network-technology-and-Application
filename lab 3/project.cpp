#define WIN32
#define HAVE_REMOTE
#include "pcap.h"
#include <iostream>
#include <WinSock2.h>
using namespace std;
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#pragma pack(1)
typedef struct Frame_Header//帧首部
{
	BYTE DesMAC[6];  //目的地址
	BYTE SrcMAC[6];  //源地址
	WORD FrameType;  //帧类型
};
typedef struct ARP_Frame//ARP数据
{
	Frame_Header FrameHeader;
	WORD HardwareType; //硬件类型
	WORD ProtocolType; //协议类型
	BYTE HLen; //硬件长度
	BYTE PLen; //协议长度
	WORD op; //操作类型
	BYTE SrcMAC[6]; //源MAC地址
	DWORD SrcIP; //源IP地址
	BYTE DesMAC[6]; //目的MAC地址
	DWORD DesIP; //目的IP地址
};

void* getaddress(struct sockaddr* sa)//得到对应的IP地址
{
	if (sa->sa_family == AF_INET)
	{
		return &(((struct sockaddr_in*)sa)->sin_addr);//IPV4地址
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);//IPV6地址
}
int main() {
	/*获取设备列表，打印信息*/
	pcap_if_t* d; //遍历用的指针
	pcap_addr_t* a; //地址指针
	pcap_if_t* devices; //指向设备列表第一个
	int i = 0; //统计设备数量
	char errbuf[PCAP_ERRBUF_SIZE]; //错误信息缓冲区
	//输出错误信息
	if (pcap_findalldevs(&devices, errbuf) == -1)
	{
		cout << stderr << "查找设备失败: " << errbuf << endl;
		return 0;
	}
	//打印设备信息
	 //打印设备列表中设备信息
	pcap_if_t* count; //遍历用的指针
	char srcip[INET_ADDRSTRLEN];//本机ip
	//输出设备名和描述信息
	for (count = devices; count; count = count->next)//借助count指针从第一个设备开始访问到最后一个设备
	{
		cout << ++i << ". " << count->name;//输出设备信息和描述
		if (count->description) {
			cout << "描述：(" << count->description << ")" << endl;
		}
		for (a = count->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				char str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, getaddress((struct sockaddr*)a->addr), str, sizeof(str));//将 a->addr 强制转换为 struct sockaddr_in 类型的指针，并访问 sin_addr 成员，其中包含了 IPv4 地址。
				cout << "IP地址：" << str << endl;
				inet_ntop(AF_INET, getaddress((struct sockaddr*)a->netmask), str, sizeof(str)); //将 a->netmask 强制转换为 struct sockaddr_in 类型的指针，从a->netmask这个结构中提取子网掩码。
				cout << "子网掩码：" << str << endl;
				inet_ntop(AF_INET, getaddress((struct sockaddr*)a->broadaddr), str, sizeof(str));//将 a->netmask 强制转换为 struct sockaddr_in 类型的指针，从a->broadaddr这个结构中提取广播地址。
				cout << "广播地址：" << str << endl;
			}
		}
	}
	//设备数量为0
	if (i == 0) {
		cout << endl << "存在错误！无查找设备！" << endl;
		return 0;
	}
	cout << "----------------------------------------------" << endl;
	/*选择设备及打开网卡*/
	pcap_if_t* count2; //遍历用的指针2
	int num = 0;
	cout << "输入当前要连接的网卡序号：";
	cin >> num;
	while (num < 1 || num>11) {
		cout << "请检查网卡序号输入是否正确！" << endl;
		cout << "重新输入当前要连接的网卡序号：";
		cin >> num;
	}
	count2 = devices;
	for (int i = 1; i < num; i++) {//循环遍历指针选择第几个网卡
		count2 = count2->next;
	}
	inet_ntop(AF_INET, getaddress((struct sockaddr*)count2->addresses->addr), srcip, sizeof(srcip));
	//将 a->addr 强制转换为 struct sockaddr_in 类型的指针，并访问 sin_addr 成员，其中包含了 IPv4 地址。
	cout << "当前网络设备接口卡IP为: " << srcip << endl << "当前网络设备接口卡名字为: " << count2->name << endl;
	//打开网络接口
	//指定获取数据包最大长度为65536,可以确保程序可以抓到整个数据包
	//指定时间范围为200ms
	pcap_t* point = pcap_open(count2->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 200, NULL, errbuf);
	if (point == NULL) {
		cout << "打开当前网络接口失败" << endl;  //打开当前网络接口失败
		pcap_freealldevs(devices);
		return 0;
	}
	else {
		cout << "打开当前网络接口成功！！" << endl;
	}
	ARP_Frame send_ARPFrame;

	//获取本机的MAC地址
	//组装报文
	unsigned char mac[48];
	for (int i = 0; i < 6; i++) {
		send_ARPFrame.FrameHeader.DesMAC[i] = 0xFF; //DesMAC设置为广播地址
		send_ARPFrame.DesMAC[i] = 0x00; //DesMAC设置为0
		//SrcMAC用不到可以不设置
	}
	send_ARPFrame.FrameHeader.FrameType = htons(0x0806); //帧类型为ARP
	send_ARPFrame.HardwareType = htons(0x0001); //硬件类型为以太网
	send_ARPFrame.ProtocolType = htons(0x0800); //协议类型为IP
	send_ARPFrame.HLen = 6; //硬件地址长度为6
	send_ARPFrame.PLen = 4; //协议地址长度为4
	send_ARPFrame.op = htons(0x0001); //操作为ARP请求
	send_ARPFrame.DesIP = inet_addr(srcip); //设置为本机IP地址
	struct pcap_pkthdr* pkt_header;
	const u_char* packetData;
	int ret;
	while ((ret = pcap_next_ex(point, &pkt_header, &packetData)) >= 0)
	{
		cout << "加载中...";
		//发送构造好的数据包
		pcap_sendpacket(point, (u_char*)&send_ARPFrame, sizeof(ARP_Frame));
		if (ret == 0) {  //未捕获到数据包
			continue;
		}
		//通过报文内容比对判断是否是要发打印的ARP数据包内容
		 //result=1，捕获成功 
		else if (*(unsigned short*)(packetData + 12) == htons(0x0806) //帧类型为ARP（htons(0x0806)）
			&& *(unsigned short*)(packetData + 20) == htons(0x0002)) //操作类型为ARP响应（htons(0x0002)）
		{
			cout << endl;
			cout << "-----------------------------------------------" << endl;
			cout << "ARP数据包内容：" << endl;
			//打印数据包
			cout << "源IP地址:\t ";
			for (int i = 28; i < 32; ++i) {
				printf("%d", packetData[i]);
				if (i < 31) cout << ".";
			}
			cout << endl;
			// 提取MAC地址（0-6字节）
			cout << "源MAC地址:\t ";
			for (int i = 6; i < 12; ++i) {
				printf("%02X", packetData[i]);
				if (i < 11) cout << "-";
			}
			cout << endl;
			//用mac数组记录本机的MAC地址
			for (int i = 0; i < 6; i++)
			{
				mac[i] = *(unsigned char*)(packetData + 22 + i);
			}
			cout << "获取MAC地址成功，MAC地址为：";
			for (int i = 6; i < 12; ++i) {
				printf("%02X", packetData[i]);
				if (i < 11) cout << "-";
			}
			cout << endl;
			cout << "----------------------------------------------" << endl;
			break;
		}
	}
	//输出错误信息
	if (ret == -1) {  //调用过程发生错误
		cout << "捕获数据包出错" << endl;
		pcap_freealldevs(devices);
		return 0;
	}

	ARP_Frame rev_ARPFrame;
	/*获取目的主机的MAC地址*/
	for (int i = 0; i < 6; i++) {
		rev_ARPFrame.FrameHeader.DesMAC[i] = 0xff; //广播地址
		rev_ARPFrame.FrameHeader.SrcMAC[i] = mac[i]; //本机MAC地址
		rev_ARPFrame.DesMAC[i] = 0x00; //设置为0
		rev_ARPFrame.SrcMAC[i] = mac[i]; //本机MAC地址
	}
	rev_ARPFrame.FrameHeader.FrameType = htons(0x0806);
	rev_ARPFrame.HardwareType = htons(0x0001);
	rev_ARPFrame.ProtocolType = htons(0x0800);
	rev_ARPFrame.HLen = 6;
	rev_ARPFrame.PLen = 4;
	rev_ARPFrame.op = htons(0x0001);
	rev_ARPFrame.SrcIP = inet_addr(srcip);
	cout << "请输入目的IP地址：";
	char ip[INET_ADDRSTRLEN];
	cin >> ip;
	rev_ARPFrame.DesIP = inet_addr(ip);
	while ((ret = pcap_next_ex(point, &pkt_header, &packetData)) >= 0)//判断获取报文
	{
		//发送构造好的数据包
		cout << "加载中...";
		pcap_sendpacket(point, (u_char*)&rev_ARPFrame, sizeof(ARP_Frame));
		if (ret == 0) {  //未捕获到数据包
			continue;
		}
		//result=1，捕获成功 
		else if (*(unsigned short*)(packetData + 12) == htons(0x0806) //帧类型为ARP（htons(0x0806)）
			&& *(unsigned short*)(packetData + 20) == htons(0x0002) //操作类型为ARP响应（htons(0x0002)）
			&& *(unsigned long*)(packetData + 28) == rev_ARPFrame.DesIP)//ip地址为填入的目标IP地址
		{
			cout << endl;
			cout << "-----------------------------------------------" << endl;
			cout << "ARP数据包内容：" << endl;
			//打印数据包
			cout << "源IP地址:\t ";
			for (int i = 38; i < 42; ++i) {
				printf("%d", packetData[i]);
				if (i < 41) cout << ".";
			}
			cout << endl;

			// 提取MAC地址（0-6字节）
			cout << "源MAC地址:\t ";
			for (int i = 0; i < 6; ++i) {
				printf("%02X", packetData[i]);
				if (i < 5) cout << "-";
			}
			cout << endl;

			cout << "目的IP地址:\t ";		
			for (int i = 28; i < 32; ++i) {
				printf("%d", packetData[i]);
				if (i < 31) cout << ".";
			}
			cout << endl;
			// 提取目的MAC地址（后6字节）
			cout << "目的MAC地址:\t ";
			
			for (int i = 6; i < 12; ++i) {
				printf("%02X", packetData[i]);
				if (i < 11) cout << "-";
			}
			cout << endl;

			cout << "获取MAC地址成功，MAC地址为：";
			for (int i = 6; i < 12; ++i) {
				printf("%02X", packetData[i]);
				if (i < 11) cout << "-";
			}
			cout << endl;
			cout << "----------------------------------------------" << endl;
			break;
		}

	}
	//输出错误信息
	if (ret == -1) {  //调用过程发生错误
		cout << "捕获数据包出错" << endl;
		pcap_freealldevs(devices);
		return 0;
	}
	// 关闭设备
	pcap_close(point);
	pcap_freealldevs(devices);
	return 0;
}
