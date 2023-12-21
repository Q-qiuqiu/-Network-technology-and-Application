#include "pcap.h"
#include <WinSock2.h>
#include <string>
#include <ctime>
#include <stdio.h>
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
//多线程
HANDLE hThread;
DWORD dwThreadId;
char myip[2][100];//	网卡设备的ip
char mymask[2][100];//网卡设备的子网掩码
BYTE mymac[6];//网卡设备的mac地址
int arpnum = 0;//arp表项个数

pcap_t* point;//指向正在使用的网卡
#pragma pack(1)//以1bytes对齐

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
typedef struct IP_Header {//IP首部
	BYTE Version;//版本号
	BYTE TOS;//服务类型
	WORD TotLen;//总长度字段
	WORD ID;//标识
	WORD Flagoffset;//分段偏移
	BYTE TTL;//生命周期
	BYTE Protocol;//协议字段
	WORD Checksum;//校验和
	ULONG SrcIP;//源IP
	ULONG DstIP;//目的IP
};
//帧首部和IP首部的数据包
typedef struct Data {
	Frame_Header FrameHeader;
	IP_Header IPHeader;
	char buf[0x80];
};
//缓冲区发送的数据包结构
typedef struct Send_Packet {
	BYTE PktData[2000];// 数据缓存
	ULONG DestIP; // 目的IP地址
	bool flag = 1; // 是否有效，如果已经被转发或者超时，则置0
	clock_t time; // 判断是否超时，超时则删除
};
Send_Packet Buffer[50];//缓冲区
int bufsize = 0; //缓冲区大小
void* getaddress(struct sockaddr* sa)//得到对应的IP地址
{
	if (sa->sa_family == AF_INET)
	{
		return &(((struct sockaddr_in*)sa)->sin_addr);//IPV4地址
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);//IPV6地址
}
//路由表项
class RouteTableItem {
public:
	DWORD netmask;
	DWORD destnet;
	DWORD nextip;
	int type;//0为直接连接，1为用户添加
	RouteTableItem* nextitem;//采用链表形式存储
	RouteTableItem() {//初始化为0
		memset(this, 0, sizeof(*this));
	}
	RouteTableItem(DWORD netmask, DWORD dstnet, int type, DWORD nextip = 0) {
		this->netmask = netmask;
		this->destnet = dstnet;
		this->nextip = nextip;
		this->type = type;
	}
	void print() {//打印内容

		in_addr addr;
		memcpy(&addr, &netmask, sizeof(netmask));
		printf("子网掩码：%s\n", inet_ntoa(addr));
		memcpy(&addr, &destnet, sizeof(destnet));
		printf("目的网络：%s\n", inet_ntoa(addr));
		memcpy(&addr, &nextip, sizeof(nextip));
		printf("下一跳地址：%s\n", inet_ntoa(addr));
		printf("类型：");
		if (type == 0) {
			printf("直接相连\n");
		}
		else if (type == 1) {
			printf("用户添加\n");
		}
		printf("<=================================>\n");
	}
};
//路由表
class RouteTable {
public:
	RouteTableItem* head;
	RouteTableItem* tail;
	int num;//路由表项数
	RouteTable() {
		num = 0;
		head = new RouteTableItem(inet_addr(mymask[0]), (inet_addr(myip[0])) & (inet_addr(mymask[0])),0);
		tail = new RouteTableItem;
		head->nextitem = tail;

			RouteTableItem* temp = new RouteTableItem;
			temp->destnet = (inet_addr(myip[1])) & (inet_addr(mymask[1]));;
			temp->netmask = inet_addr(mymask[1]);
			temp->type = 0;
			add(temp);
		
	}
	//添加表项（直接投递在最前，前缀长的在前面）
	void add(RouteTableItem* newt) {
		num++;
		//直接投递
		if (newt->type == 0) {
			newt->nextitem = head->nextitem;//插入在head后
			head->nextitem = newt;
			return;
		}
		//根据掩码的大小插入
		RouteTableItem* cur = head;
		while (cur->nextitem != tail) {
			if (cur->nextitem->type != 0 && cur->nextitem->netmask <= newt->netmask) {
				break;
			}
			cur = cur->nextitem;
		}
		//插入在 cur 和 cur->next 之间
		newt->nextitem = cur->nextitem;
		cur->nextitem = newt;
	}
	//删除表项
	void Delete(int index) {
		if (index > num) {
			printf("路由表项%d超过范围!\n", index);
			return;
		}
		if (index == 0) { //删除头部
			if (head->type == 0) {
				printf("默认路由不可删除!\n");
			}
			else {
				head = head->nextitem;
			}
			return;
		}
		RouteTableItem* cur = head;
		int i = 0;
		while (i < index - 1 && cur->nextitem != tail) { //指针指向删除的位置
			i++;
			cur = cur->nextitem;
		}
		if (cur->nextitem->type == 0) {
			printf("默认路由不可删除!\n");
		}
		else {
			cur->nextitem = cur->nextitem->nextitem;
		}

	}
	//路由表打印
	void print() {
		printf("<==============路由表=============>\n");
		RouteTableItem* cur = head;
		int i = 1;
		while (cur != tail) {
			printf("【第%d条路由表项】\n", i);
			cur->print();
			cur = cur->nextitem;
			i++;
		}
	}
	//查找，最长前缀,返回下一跳的ip
	DWORD find(DWORD destip) {
		DWORD result;
		RouteTableItem* cur = head;
		while (cur != tail) {
			result = destip & cur->netmask;
			if (result == cur->destnet) {
				if (cur->type == 1) {
					return cur->nextip;//转发
				}
				else if (cur->type == 0) {
					return destip;//直接投递
				}
			}
			cur = cur->nextitem;
		}
		printf("没有找到对应的路由表项!\n");
		return -1;
	}
};
//ARP表
class ARPTable
{
public:
	DWORD IP;//IP
	BYTE mac[6];//MAC
	//添加
	void add(DWORD ip, BYTE mac[6])
	{
		arp_table[arpnum].IP = ip;
		for (int i = 0; i < 6; i++)
		{
			arp_table[arpnum].mac[i] = mac[i];
		}
		//memcpy(arp_table[arpnum].mac, mac, 6);
		arpnum++;
	}
	//查找
	int find(DWORD ip, BYTE mac[6])
	{
		for (int i = 0; i < arpnum; i++)
		{
			if (ip == arp_table[i].IP)
			{
				for (int j = 0; j < 6; j++)
				{
					mac[j] = arp_table[i].mac[j];
				}
				//memcpy(mac, arp_table[i].mac, 6);
				return 1;
			}
		}
		return 0;
	}
}arp_table[50];//最大数50

//设置校验和
void SetChecksum(Data* temp)
{
	temp->IPHeader.Checksum = 0;
	unsigned long sum = 0;
	WORD* buffer = (WORD*)&temp->IPHeader;//每16位为一组
	int size = sizeof(IP_Header);
	while (size > 1)
	{
		sum += *buffer++;
		// 16位相加
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		// 最后可能有单独8位
		sum += *(unsigned char*)buffer;
	}
	// 将高16位进位加至低16位
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	// 取反
	temp->IPHeader.Checksum = ~sum;
}
//检验校验和
bool Check(Data* temp)
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IP_Header) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//包含原有校验和一起进行相加
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)//源码+反码->全1
		return 1;//校验和正确
	return 0;
}
//转发
void communicate(Data data, BYTE nextmac[])
{
	//拷贝数据包
	Data* temp = (Data*)&data;
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//源MAC为本机MAC
	memcpy(temp->FrameHeader.DesMAC, nextmac, 6);//目的MAC为下一跳MAC
	temp->IPHeader.TTL -= 1;//TTL-1
	if (temp->IPHeader.TTL < 0)return;//丢弃
	SetChecksum(temp);//重新设置校验和
	printf("<==============转发===============>\n");
	//打印IP数据包
	printf("源MAC地址:\t ");
	for (int i = 0; i < 5; i++) {
		printf("%02X-", temp->FrameHeader.SrcMAC[i]);
	}
	printf("%02X\n", temp->FrameHeader.SrcMAC[5]);

	printf("目的MAC地址:\t");
	for (int i = 0; i < 5; i++) {
		printf("%02X-", temp->FrameHeader.DesMAC[i]);
	}
	printf("%02X\n", temp->FrameHeader.DesMAC[5]);
	printf("源IP地址:\t ");
	in_addr addr;
	memcpy(&addr, &temp->IPHeader.SrcIP, sizeof(temp->IPHeader.SrcIP));
	printf("%s  ", inet_ntoa(addr));
	printf("\n");
	printf("目的IP地址:\t ");
	memcpy(&addr, &temp->IPHeader.DstIP, sizeof(temp->IPHeader.DstIP));
	printf("%s  ", inet_ntoa(addr));
	printf("\n");
	printf("TTL: %d\n", temp->IPHeader.TTL); // 十进制输出
	pcap_sendpacket(point, (const u_char*)temp, 74);//发送数据报
}
//比较两数组是否相同
bool compare(BYTE a[], BYTE b[])
{
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
		{
			return false;
		}
	}
	return true;
}
//获取目的主机MAC地址
void getdestmac(DWORD ip, BYTE mac[])
{
	//初始化ARP数据包
	ARP_Frame rev_ARPFrame;
	/*获取目的主机的MAC地址*/
	for (int i = 0; i < 6; i++) {
		rev_ARPFrame.FrameHeader.DesMAC[i] = 0xff; //广播地址
		rev_ARPFrame.FrameHeader.SrcMAC[i] = mac[i]; //MAC地址
		rev_ARPFrame.DesMAC[i] = 0x00; //设置为0
		rev_ARPFrame.SrcMAC[i] = mymac[i]; //本机MAC地址
	}
	rev_ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	rev_ARPFrame.HardwareType = htons(0x0001); //硬件类型为以太网
	rev_ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	rev_ARPFrame.HLen = 6;//硬件地址长度为6
	rev_ARPFrame.PLen = 4;//协议类型长度为4
	rev_ARPFrame.op = htons(0x0001);//操作为ARP请求	
	rev_ARPFrame.SrcIP = inet_addr(myip[0]);//设置发送方ip地址
	rev_ARPFrame.DesIP = ip;
	//发送数据包
	pcap_sendpacket(point, (u_char*)&rev_ARPFrame, sizeof(ARP_Frame));
}
//接收线程函数
DWORD WINAPI receive(LPVOID lparam)
{
	ARPTable arptable;
	RouteTable rtable = *(RouteTable*)(LPVOID)lparam;
	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* packetData;
		//等待接收消息
		while (1)
		{
			int result = pcap_next_ex(point, &pkt_header, &packetData);
			if (result)
			{
				break;//接收到消息
			}
		}
		Frame_Header* header = (Frame_Header*)packetData;
		//数据包是ARP格式
		if (ntohs(header->FrameType) == 0x806)
		{
			ARP_Frame* data = (ARP_Frame*)packetData;//格式化收到的包为帧首部+ARP首部类
			printf("<==============接收ARP===============>\n");
			//打印ARP数据包
			// 提取MAC地址（0-6字节）
			printf("源MAC地址:\t ");
			for (int i = 0; i < 5; i++) {
				printf("%02X-", data->FrameHeader.SrcMAC[i]);
			}
			printf("%02X\n", data->FrameHeader.SrcMAC[5]);

			printf("目的MAC地址:\t");
			for (int i = 0; i < 5; i++) {
				printf("%02X-", data->FrameHeader.DesMAC[i]);
			}
			printf("%02X\n", data->FrameHeader.DesMAC[5]);
			printf("源IP地址:\t ");
			in_addr addr;
			memcpy(&addr, &data->SrcIP, sizeof(data->SrcIP));
			printf("%s  ", inet_ntoa(addr));
			printf("\n");
			printf("目的IP地址:\t ");
			memcpy(&addr, &data->DesIP, sizeof(data->DesIP));
			printf("%s  ", inet_ntoa(addr));
			printf("\n");
			//收到ARP响应包
			if (data->op == ntohs(0x0002)) {
				BYTE tempmac[6];
				//该映射关系已经存到arp表中，不做处理
				if (arptable.find(data->SrcIP, tempmac)) {
				}
				//不在arp表中，插入
				else
				{
					arptable.add(data->SrcIP, data->SrcMAC);
				}
				//遍历缓冲区，看是否有可以转发的包
				for (int i = 0; i < bufsize; i++)
				{
					if (Buffer[i].flag == 0)continue;
					if (clock() - Buffer[i].time >= 6000) {//超时
						Buffer[i].flag = 0;
						continue;
					}
					if (Buffer[i].DestIP == data->SrcIP)
					{
						Data* data_send = (Data*)Buffer[i].PktData;
						Data temp = *data_send;
						communicate(temp, data->SrcMAC);
						Buffer[i].flag = 0;
						break;
					}
				}
			}
		}
		//目的mac是自己的mac且数据包是IP格式
		if (compare(header->DesMAC, mymac) && ntohs(header->FrameType) == 0x800)
		{
			Data* data = (Data*)packetData; //格式化收到的包
			//如果校验和不正确，则直接丢弃不进行处理
			if (!Check(data))
			{
				printf("校验和出错\n");
				continue;
			}
			printf("<==============接收IP===============>\n");
			//打印IP数据包
			printf("源MAC地址:\t ");
			for (int i = 6; i < 12; ++i) {
				printf("%02X", packetData[i]);
				if (i < 11) printf("-");
			}
			printf("\n");
			printf("目的MAC地址:\t");
			for (int i = 0; i < 6; ++i) {
				printf("%02X", packetData[i]);
				if (i < 5) printf("-");
			}
			printf("\n");
			printf("源IP地址:\t ");
			for (int i = 26; i < 30; ++i) {
				printf("%d", packetData[i]);
				if (i < 29) printf(".");
			}
			printf("\n");
			printf("目的IP地址:\t ");
			for (int i = 30; i < 34; ++i) {
				printf("%d", packetData[i]);
				if (i < 33) printf(".");
			}
			printf("\n");
			printf("TTL: %d\n", data->IPHeader.TTL); // 十进制输出
			if (data->IPHeader.DstIP == inet_addr(myip[0]) || data->IPHeader.DstIP == inet_addr(myip[1]))//路由器两个网卡都可以接受
			{
				printf("发送给自己的数据包,交由电脑处理\n");
				continue;
			}
			printf("<=================================>\n");
			DWORD destip = data->IPHeader.DstIP; //目的IP地址
			DWORD nextdestip = rtable.find(destip);//查找下一跳IP地址
			
			if (nextdestip == -1)
			{
				printf("路由表项缺失！\n");
				continue;//如果没有则直接丢弃或直接递交至上层
			}
			else
			{
				in_addr next;
				next.s_addr = nextdestip;
				printf("下一跳IP：%s\n", inet_ntoa(next));

				Data* temp2 = (Data*)packetData;
				Data temp = *temp2;
				BYTE mac[6];
				//直接投递
				if (nextdestip == destip)
				{
					//如果ARP表中没有所需内容，则需要获取ARP
					if (!arptable.find(destip, mac))
					{
						int flag2 = 0;
						for (int i = 0; i < bufsize; i++)
						{
							if (Buffer[i].flag == 0) //如果缓冲区中有已经被转发的，将数据包复制到该转发完成的数据包（覆盖用过的地方，节省空间）
							{
								flag2 = 1;
								memcpy(Buffer[i].PktData, packetData, pkt_header->len);
								Buffer[i].flag = 1;
								Buffer[i].time = clock();
								Buffer[i].DestIP = destip;
								getdestmac(destip, mac);
								break;
							}
						}
						if (flag2 == 0 && bufsize < 50) //缓冲区上限50
						{
							memcpy(Buffer[bufsize].PktData, packetData, pkt_header->len);
							Buffer[bufsize].flag = 1;
							Buffer[bufsize].time = clock();
							Buffer[bufsize].DestIP = destip;
							bufsize++;
							getdestmac(destip, mac);
						}
						else {
							printf("缓冲区溢出！\n");
						}
					}
					else if(arptable.find(destip, mac))
					{
						communicate(temp, mac);//转发
					}
				}
				else //不是直接投递
				{
					if (!arptable.find(nextdestip, mac))
					{
						int flag3 = 0;
						for (int i = 0; i < bufsize; i++)
						{
							if (Buffer[i].flag == 0)
							{
								flag3 = 1;
								memcpy(Buffer[i].PktData, packetData, pkt_header->len);
								Buffer[i].flag = 1;
								Buffer[i].time = clock();
								Buffer[i].DestIP = nextdestip;
								getdestmac(nextdestip, mac);
								break;
							}
						}
						if (flag3 == 0 && bufsize < 50)
						{
							memcpy(Buffer[bufsize].PktData, packetData, pkt_header->len);
							Buffer[bufsize].flag = 1;
							Buffer[bufsize].time = clock();
							Buffer[bufsize].DestIP = nextdestip;
							bufsize++;
							getdestmac(nextdestip, mac);
						}
						else if (arptable.find(destip, mac))
						{
							communicate(temp, mac);//转发
						}
					}
					else if (arptable.find(nextdestip, mac))
					{
						communicate(temp, mac);
					}
				}
			}
		}
	}
}
int main() {
	char errbuf[PCAP_ERRBUF_SIZE]; //错误信息缓冲区
	/*获取设备列表，打印信息*/
	pcap_addr_t* a; //地址指针
	pcap_if_t* devices; //指向设备列表第一个
	int i = 0; //统计设备数量
	//输出错误信息
	if (pcap_findalldevs(&devices, errbuf) == -1)
	{
		printf("查找设备失败: %s\n", errbuf);

		return 0;
	}
	//打印设备信息
	 //打印设备列表中设备信息
	pcap_if_t* count; //遍历用的指针
	//输出设备名和描述信息
	for (count = devices; count; count = count->next)//借助count指针从第一个设备开始访问到最后一个设备
	{
		printf("%d. %s", ++i, count->name);//输出设备信息和描述
		if (count->description) {
			printf("描述：(%s)\n", count->description);

		}
		for (a = count->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				char str[100];

				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				//inet_ntop(AF_INET, getaddress((struct sockaddr*)a->addr), str, sizeof(str));//将 a->addr 强制转换为 struct sockaddr_in 类型的指针，并访问 sin_addr 成员，其中包含了 IPv4 地址。
				printf("IP地址：%s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
				//inet_ntop(AF_INET, getaddress((struct sockaddr*)a->netmask), str, sizeof(str)); //将 a->netmask 强制转换为 struct sockaddr_in 类型的指针，从a->netmask这个结构中提取子网掩码。
				printf("子网掩码：%s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->broadaddr)->sin_addr));
				//inet_ntop(AF_INET, getaddress((struct sockaddr*)a->broadaddr), str, sizeof(str));//将 a->netmask 强制转换为 struct sockaddr_in 类型的指针，从a->broadaddr这个结构中提取广播地址。
				printf("广播地址：%s\n", str);

			}
		}
	}
	//设备数量为0
	if (i == 0) {
		printf("存在错误！无查找设备！");
		return 0;
	}
	printf("<============================================>\n");
	/*选择设备及打开网卡*/
	pcap_if_t* count2; //遍历用的指针2
	int num = 0;
	printf("输入当前要连接的网卡序号：");
	scanf("%d", &num);

	while (num < 1 || num>2) {
		printf("请检查网卡序号输入是否正确！");
		printf("重新输入当前要连接的网卡序号：");
		scanf("%d", &num);

	}
	count2 = devices;
	for (int i = 1; i < num; i++) {//循环遍历指针选择第几个网卡
		count2 = count2->next;
	}
	int k = 0;
	//储存ip和子网掩码
	for (a = count2->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family == AF_INET) {
			printf("接口卡名称:：(%s)\n", count2->name);
			printf("接口卡描述：(%s)\n", count2->description);
			//将 a->addr 强制转换为 struct sockaddr_in 类型的指针，并访问 sin_addr 成员，其中包含了 IPv4 地址。
			strcpy(myip[k], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			printf("IP地址：%s\n", myip);
			strcpy(mymask[k], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
			//将 a->netmask 强制转换为 struct sockaddr_in 类型的指针，从a->netmask这个结构中提取子网掩码。
			printf("子网掩码：%s\n", mymask);
			k++;
		}
	}
	//打开网络接口
	//指定获取数据包最大长度为65536,可以确保程序可以抓到整个数据包，指定时间范围为200ms
	point = pcap_open(count2->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 200, NULL, errbuf);
	if (point == NULL) { //打开当前网络接口失败
		printf("打开当前网络接口失败");
		return 0;
	}
	else {
		printf("打开当前网络接口成功！");
	}
	pcap_freealldevs(devices);
	//获取本机的MAC地址
	//组装报文
	ARP_Frame send_ARPFrame;
	for (int i = 0; i < 6; i++) {
		send_ARPFrame.FrameHeader.DesMAC[i] = 0xFF; //DesMAC设置为广播地址
		send_ARPFrame.DesMAC[i] = 0x00; //DesMAC设置为0
		//SrcMAC用不到可以不设置
	}
	send_ARPFrame.FrameHeader.FrameType = htons(0x0806); //帧类型为ARP，0x8100是一个IEEE 802.1Q帧，0x86DD是一个IPv6帧，0x0800代表 IP协议帧等
	send_ARPFrame.HardwareType = htons(0x0001); //硬件类型为以太网，IEEE 802 网络是 0x0006，Bluetooth是0x00FF等
	send_ARPFrame.ProtocolType = htons(0x0800); //协议类型为IPv4，IPv6是0x86DD，
	send_ARPFrame.HLen = 6; //硬件地址长度为6
	send_ARPFrame.PLen = 4; //协议地址长度为4
	send_ARPFrame.op = htons(0x0001); //操作为ARP请求，ARP响应是 0x0002
	send_ARPFrame.DesIP = inet_addr(myip[0]); //设置为本机IP地址
	pcap_sendpacket(point, (u_char*)&send_ARPFrame, sizeof(ARP_Frame));

	struct pcap_pkthdr* pkt_header;
	const u_char* packetData;
	int ret;
	while ((ret = pcap_next_ex(point, &pkt_header, &packetData)) >= 0)//判断获取报文
	{
		printf("加载中...");
		if (ret == 0) {  //未捕获到数据包
			continue;
		}
		//通过报文内容比对判断是否是要发打印的ARP数据包内容
		 //result=1，捕获成功 
		else if (*(unsigned short*)(packetData + 12) == htons(0x0806) //帧类型为ARP（htons(0x0806)）
			&& *(unsigned short*)(packetData + 20) == htons(0x0002)
			&& *(unsigned long*)(packetData + 28) == send_ARPFrame.DesIP) //操作类型为ARP响应（htons(0x0002)）
		{
			printf("\n");
			printf("<=================================>\n");
			//用mac数组记录本机的MAC地址
			for (int i = 0; i < 6; i++)
			{
				mymac[i] = *(unsigned char*)(packetData + 22 + i);
			}
			printf("获取MAC地址为：\t ");
			for (int i = 6; i < 12; ++i) {
				printf("%02X", packetData[i]);
				if (i < 11) printf("-");
			}
			printf("\n");
			printf("<=================================>\n");
			break;
		}
	}
	//输出错误信息
	if (ret == -1) {  //调用过程发生错误
		printf("捕获数据包出错\n");
		pcap_freealldevs(devices);
		return 0;
	}

	struct bpf_program fcode;
	//通过绑定过滤器，设置只捕获IP和ARP数据报
	//编辑过滤字符串
	if (pcap_compile(point, &fcode, "ip or arp", 1, bpf_u_int32(inet_addr(mymask[0]))) < 0)
	{
		fprintf(stderr, "\n设置过滤器失败！\n");
		system("pause");
		return 0;
	}
	//绑定过滤器
	if (pcap_setfilter(point, &fcode) < 0)
	{
		fprintf(stderr, "\n绑定过滤器失败！\n");
		system("pause");
		return 0;
	}
	RouteTable rtable; //路由表初始化
	rtable.print();//输出路由表中的默认项

	hThread = CreateThread(NULL, NULL, receive, LPVOID(&rtable), 0, &dwThreadId);
	while (1)
	{
		printf("请选择要进行的操作：\n");
		printf("【1.添加路由表项】\t【2.删除路由表项】\t【3.查看路由表项】\n");
		int num;
		scanf("%d", &num);
		if (num == 1)
		{
			RouteTableItem* rtableitem = new RouteTableItem;
			rtableitem->type = 1;//用户添加
			char buf[INET_ADDRSTRLEN];
			printf("请输入子网掩码:\n");
			scanf("%s", &buf);
			rtableitem->netmask = inet_addr(buf);
			printf("输入目的网络:\n");
			scanf("%s", &buf);
			rtableitem->destnet = inet_addr(buf);
			printf("请输入下一跳IP地址:\n");
			scanf("%s", &buf);
			rtableitem->nextip = inet_addr(buf);
			rtable.add(rtableitem);
		}
		else if (num == 2)
		{
			printf("请输入删除的序号：");
			int index;
			scanf("%d", &index);

			rtable.Delete(index - 1);//将链表序号与实际输入序号统一
		}
		else if (num == 3)
		{
			rtable.print();
		}
		else
		{
			printf("输入有误！请重新输入!\n");
		}
	}
	return 0;
}
