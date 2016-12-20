// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xd5;
        pchMessageStart[1] = 0x3b;
        pchMessageStart[2] = 0x52;
        pchMessageStart[3] = 0xc5;
        vAlertPubKey = ParseHex("0486bce1bac0d543f104cbff2bd23680056a3b9ea05e1137d2ff90eeb5e08472eb500322593a2cb06fbf8297d7beb6cd30cb90f98153b5b7cce1493749e41e0284");
        nDefaultPort = 3567;
        nRPCPort = 3568;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20);

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
        //
        //CBlock(hash=000001faef25dec4fbcf906e6242621df2c183bf232f263d0ba5b101911e4563, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90, nTime=1393221600, nBits=1e0fffff, nNonce=164482, vtx=1, vchBlockSig=)
        //  Coinbase(hash=12630d16a9, nTime=1393221600, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //    CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a24323020466562203230313420426974636f696e2041544d7320636f6d6520746f20555341)
        //    CTxOut(empty)
        //  vMerkleTree: 12630d16a9
        const char* pszTimestamp = "2016/12/9 19:22:52";
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
        CTransaction txNew(1, 1480950368, vin, vout, 0);
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1480950368;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 146586;

        CBigNum bnTarget;
        bnTarget.SetCompact(genesis.nBits);

        while (genesis.GetHash()> bnTarget.getuint256())
        {
            if (genesis.nNonce % 1048576 == 0)
                printf("n=%dM hash=%s\n", genesis.nNonce / 1048576,
                       genesis.GetHash().ToString().c_str());
            genesis.nNonce++;
        }

        hashGenesisBlock = genesis.GetHash();

       /* ofstream f;
        f.open("1.txt");
        f<<"Hash = "<<hashGenesisBlock.ToString()<<"\n";
        f<<"hashMerkleRoot = "<<genesis.hashMerkleRoot.ToString()<<"\n";
        f<<"nTime ="<<genesis.nTime<<"\n";
        f<<"nNonce ="<<genesis.nNonce<<"\n";
        f.close();*/
		
#if 0
        printf("hashGenesisBlock = %s\n",hashGenesisBlock.ToString().c_str());
        printf("nNonce =%d\n",genesis.nNonce);
        printf("hashMerkleRoot = %s\n",genesis.hashMerkleRoot.ToString().c_str());
#endif
        assert(hashGenesisBlock == uint256("0x0000051f24d7e13a08edd39f5adc73fec5c5d7a50cf635af06d0e1b4826d494a"));
        assert(genesis.hashMerkleRoot == uint256("0x40c571ea9015d0f85d3a36a5cd229ac88f10043ceb6171051d5d94d121d7e42b"));

        char *seeds[][2] ={
            "118.192.149.155", "118.192.149.155",
            "118.192.149.155", "118.192.149.150",
            "118.192.149.155", "118.192.149.149"
                          };
        for(size_t i = 0;i<sizeof(seeds)/sizeof(char*)/2;i++)
        {
                vSeeds.push_back(CDNSSeedData(string(seeds[i][0]),string(seeds[i][1])));
        }


       // vSeeds.push_back(CDNSSeedData("118.192.149.155", "118.192.149.155"));
        //vSeeds.push_back(CDNSSeedData("118.192.149.150", "118.192.149.150"));
        //vSeeds.push_back(CDNSSeedData("118.192.149.149", "118.192.149.149"));
        base58Prefixes[PUBKEY_ADDRESS] = list_of(55);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(117);
        base58Prefixes[SECRET_KEY] =     list_of(153);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        nLastPOWBlock = 10000;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xef;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        vAlertPubKey = ParseHex("0471dc165db490094d35cde15b1f5d755fa6ad6f2b5ed0f340e3f17f57389c3c2af113a8cbcc885bde73305a553b5640c83021128008ddf882e856336269080496");
        nDefaultPort = 25744;
        nRPCPort = 25745;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 15363;		
		
        CBigNum bnTarget;
        bnTarget.SetCompact(genesis.nBits);

        while (genesis.GetHash()> bnTarget.getuint256())
        {
            if (genesis.nNonce % 1048576 == 0)
                printf("n=%dM hash=%s\n", genesis.nNonce / 1048576,
                       genesis.GetHash().ToString().c_str());
            genesis.nNonce++;
        }

        hashGenesisBlock = genesis.GetHash();
     /*   ofstream f;
        f.open("2.txt");
        f<<"Hash = "<<hashGenesisBlock.ToString()<<"\n";
        f<<"hashMerkleRoot = "<<genesis.hashMerkleRoot.ToString()<<"\n";
        f<<"nTime ="<<genesis.nTime<<"\n";
        f<<"nNonce ="<<genesis.nNonce<<"\n";
        f.close();*/

#if 0
        printf("hashGenesisBlock = %s\n",hashGenesisBlock.ToString().c_str());
        printf("nNonce =%d\n",genesis.nNonce);
        printf("hashMerkleRoot = %s\n",genesis.hashMerkleRoot.ToString().c_str());
#endif
        assert(hashGenesisBlock == uint256("0x000028be968d209bc53d8380e43b25bf117c0cfe938532fc38eb42b881d115b6"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = list_of(111);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        nLastPOWBlock = 0x7fffffff;
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 1480950368;
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 67;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18444;
        strDataDir = "regtest";
        CBigNum bnTarget;
        bnTarget.SetCompact(genesis.nBits);

        while (genesis.GetHash()> bnTarget.getuint256())
        {
            if (genesis.nNonce % 1048576 == 0)
                printf("n=%dM hash=%s\n", genesis.nNonce / 1048576,
                       genesis.GetHash().ToString().c_str());
            genesis.nNonce++;
        }

        hashGenesisBlock = genesis.GetHash();
		

       /* ofstream f;
        f.open("3.txt");
        f<<"Hash = "<<hashGenesisBlock.ToString()<<"\n";
        f<<"hashMerkleRoot = "<<genesis.hashMerkleRoot.ToString()<<"\n";
        f<<"nTime ="<<genesis.nTime<<"\n";
        f<<"nNonce ="<<genesis.nNonce<<"\n";
        f.close();*/
#if 0
        printf("hashGenesisBlock = %s\n",hashGenesisBlock.ToString().c_str());
        printf("nNonce =%d\n",genesis.nNonce);
        printf("hashMerkleRoot = %s\n",genesis.hashMerkleRoot.ToString().c_str());
#endif
        assert(hashGenesisBlock == uint256("0x2a2097db8b4d839b3df740511fbb90168821474645b21d59024a2ca81fa324c9"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
