#include<iostream>
#include "rawsocsniffer.h"
using namespace std;
int main(){

    rawsocsniffer Mysniffer(htons(ETH_P_ALL));
    if(Mysniffer.init()){

        filter f;

        char answer;
        cout << "Set Filter ? (y or n): ";
        cin >> answer;
        if(answer == 'y'){
            //设置协议
            cout << "  Set Protocol ? (y or n): ";
            cin>> answer;
            if(answer == 'y'){
                cout << "   include ARP ? (y or n): ";
                cin >> answer;
                if(answer == 'y')
                    Mysniffer.setbit(f.protocol, 1);

                cout << "   include TCP ? (y or n): ";
                cin >> answer;
                if(answer == 'y')
                    Mysniffer.setbit(f.protocol, 2);

                cout << "   include UDP ? (y or n): ";
                cin >> answer;
                if(answer == 'y')
                    Mysniffer.setbit(f.protocol, 3);

                cout << "   include ICMP ? (y or n): ";
                cin >> answer;
                if(answer == 'y')
                    Mysniffer.setbit(f.protocol, 4);

                cout << "   include RARP ? (y or n): ";
                cin >> answer;
                if(answer == 'y')
                Mysniffer.setbit(f.protocol, 5);

                if(f.protocol == 0){
                    //全部为0，则全部分析，即把protocol的1-5位全部设置为1
                    Mysniffer.setbit(f.protocol, 1);
                    Mysniffer.setbit(f.protocol, 2);
                    Mysniffer.setbit(f.protocol, 3);
                    Mysniffer.setbit(f.protocol, 4);
                    Mysniffer.setbit(f.protocol, 5);
                }
                }else if(answer == 'n'){

                    //不设置则全部分析，即把protocol的1-5位全部设置为1
                    Mysniffer.setbit(f.protocol, 1);
                    Mysniffer.setbit(f.protocol, 2);
                    Mysniffer.setbit(f.protocol, 3);
                    Mysniffer.setbit(f.protocol, 4);
                    Mysniffer.setbit(f.protocol, 5);
                }

                //设置源ip
            cout<<"  Set Src IP ? (y or n): ";
            cin >> answer;
            if(answer == 'y'){
                char srcIP[16];
                cout << "   Src IP : ";
                cin >> srcIP;
                f.sip = inet_addr(srcIP);
            }else
                f.sip = 0;

            //设置目的ip
            cout<<"  Set Des IP ? (y or n): ";
            cin >> answer;
            if(answer == 'y'){
                char desIP[16];
                cout << "   Des IP : ";
                cin >> desIP;
                f.dip = inet_addr(desIP);
            }else
                f.dip = 0;

           
        }else{

             Mysniffer.setbit(f.protocol, 1);
             Mysniffer.setbit(f.protocol, 2);
             Mysniffer.setbit(f.protocol, 3);
             Mysniffer.setbit(f.protocol, 4);
             Mysniffer.setbit(f.protocol, 5);

             f.sip = 0;

             f.dip = 0;

             Mysniffer.setfilter(f);
        }

       

        Mysniffer.setfilter(f);
        Mysniffer.sniffer();
        
    }else
        cout<<"sniffer init failed!"<<endl;
    

}