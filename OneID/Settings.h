#include <string>
#include <string>

#define OPT_PSE		0x01
#define OPT_NONCE	0x02
#define OPT_LINK	0x04
#define OPT_PUBKEY	0x08
#define IAS_API_DEF_VERSION    3 
#define DEFAULT_CA_BUNDLE_LINUX	DEFAULT_CA_BUNDLE_AUTO

using namespace std;

namespace Settings {
    static int QUERY_IAS_PRODUCTION = 0;
    static string SPID = "FEF23C7E73A379823CE71FF289CFBC07";
    static int LINKABLE = 1;
    static int RANDOM_NONCE = 1;
    static int USE_PLATFORM_SERVICES = 0;
    static char *IAS_PRIMARY_SUBSCRIPTION_KEY = "e2e08166ca0f41ef88af2797f007c7cd";
    static char *IAS_SECONDARY_SUBSCRIPTION_KEY = "2ecdd9cb7a004f3e8e0e45ed2ebd1fb4";
    static string IAS_REPORT_SIGNING_CA_FILE = "Intel_SGX_Attestation_RootCA.pem";
    static char *USERAGENT = NULL;
    static string server = "localhost";
    static string port = "7777";
    static int flags = OPT_LINK;
    static char debug = 0;
    static char verbose = 0;
}
