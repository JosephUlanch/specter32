#include "packet.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <random>
#include <vector>
using namespace specter;
const uint8_t target[] = {0x10,0x20,0x30,0x40,0x50,0x60};
std::vector<uint8_t> key(unsigned message, bool qos=false, bool ht=false) {
    size_t h = 24 + (qos ? 2 : 0) + (ht ? 4 : 0);
    std::vector<uint8_t> p(h + 8 + 99, 0);
    bool ap = message == 1 || message == 3;
    p[0] = qos ? 0x88 : 0x08; p[1] = (ap ? 2 : 1) | (ht ? 0x80 : 0);
    memcpy(p.data() + (ap ? 10 : 4), target, 6);
    const uint8_t llc[] = {0xaa,0xaa,3,0,0,0,0x88,0x8e};
    memcpy(p.data()+h,llc,8);
    uint8_t* e = p.data()+h+8; e[0]=2;e[1]=3;e[3]=95;e[4]=2;
    unsigned info = 8 | (ap ? 0x80 : 0) | (message != 1 ? 0x100 : 0) | (message >= 3 ? 0x200 : 0);
    e[5]=info>>8;e[6]=info;
    return p;
}
int main(int argc, char** argv) {
    for(unsigned m=1;m<=4;++m) for(unsigned variant=0;variant<3;++variant) {
        auto p=key(m,variant>0,variant==2);
        auto r=parse(p.data(),p.size(),target);
        assert(r.kind==Kind::Eapol && r.message==m);
        for(size_t n=0;n<p.size();++n) assert(parse(p.data(),n,target).kind==Kind::Ignore);
        p[1]|=0x40; assert(parse(p.data(),p.size(),target).kind==Kind::Ignore);
    }
    auto p=key(2); p[4]^=1; assert(parse(p.data(),p.size(),target).kind==Kind::Ignore);
    p=key(2);p[1]|=4;assert(parse(p.data(),p.size(),target).kind==Kind::Ignore);
    p=key(2);p[22]=1;assert(parse(p.data(),p.size(),target).kind==Kind::Ignore);
    p=key(2);p[1]=3;assert(parse(p.data(),p.size(),target).kind==Kind::Ignore);
    p=key(2,true);p[24]=0x80;assert(parse(p.data(),p.size(),target).kind==Kind::Ignore);
    p=key(2);p[32+6]&=~8;assert(parse(p.data(),p.size(),target).message==0);
    p=key(2);p[32+98]=1;assert(parse(p.data(),p.size(),target).message==0);
    p=key(2);p[32+2]=0xff;assert(parse(p.data(),p.size(),target).kind==Kind::Ignore);
    std::array<uint8_t,36> beacon{};beacon[0]=0x80;memcpy(beacon.data()+16,target,6);
    assert(parse(beacon.data(),beacon.size(),target).kind==Kind::Beacon);
    assert(parse(beacon.data(),35,target).kind==Kind::Ignore);
    std::mt19937 rng(32);
    for(unsigned i=0;i<100000;++i){std::vector<uint8_t> random(rng()%1700);for(auto& b:random)b=rng();parse(random.data(),random.size(),target);}
    uint8_t global[24],record[16];pcapHeader(global);recordHeader(record,1234567,131);
    assert(global[0]==0xd4 && global[20]==105 && record[0]==1);
    if(argc>1){FILE* f=fopen(argv[1],"wb");assert(f);fwrite(global,1,24,f);for(unsigned m=1;m<=4;++m){p=key(m);recordHeader(record,1000000+m*100,p.size());fwrite(record,1,16,f);fwrite(p.data(),1,p.size(),f);}fclose(f);}
    puts("Packet parser: M1-M4, QoS/HT, truncation, filters, 100k fuzz inputs and PCAP passed.");
}
