#include "internal.h"

#include "ccan/ccan/crypto/ripemd160/ripemd160.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "script_int.h"

#include <include/wally_address.h>
#include <include/wally_bip32.h>
#include <include/wally_crypto.h>
#include <include/wally_psbt.h>
#include <include/wally_script.h>
#include <include/wally_descriptor.h>

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>

#define NUM_ELEMS(a) (sizeof(a) / sizeof(a[0]))

/* Definitions */
/* Properties and expressions definition */
#define TYPE_B     0x01  /* Base expressions */
#define TYPE_V     0x02  /* Verify expressions */
#define TYPE_K     0x04  /* Key expressions */
#define TYPE_W     0x08  /* Wrapped expressions */
#define TYPE_MASK  0x0F  /* expressions mask */

#define PROP_Z  0x00000100  /* Zero-arg property */
#define PROP_O  0x00000200  /* One-arg property */
#define PROP_N  0x00000400  /* Nonzero arg property */
#define PROP_D  0x00000800  /* Dissatisfiable property */
#define PROP_U  0x00001000  /* Unit property */
#define PROP_E  0x00002000  /* Expression property */
#define PROP_F  0x00004000  /* Forced property */
#define PROP_S  0x00008000  /* Safe property */
#define PROP_M  0x00010000  /* Nonmalleable property */
#define PROP_X  0x00020000  /* Expensive verify */

#define DESCRIPTOR_KIND_MINISCRIPT  0x01
#define DESCRIPTOR_KIND_DESCRIPTOR  0x02    /* Output Descriptor */

#define DESCRIPTOR_KIND_FRAGMENT  0x01
#define DESCRIPTOR_KIND_SCRIPT    0x02    /* Output Descriptor script */
#define DESCRIPTOR_KIND_RAW       0x04    /* Output Descriptor */
#define DESCRIPTOR_KIND_NUMBER    0x08    /* Output Descriptor */
#define DESCRIPTOR_KIND_ADDRESS   0x10    /* Output Descriptor */
#define DESCRIPTOR_KIND_KEY       0x20    /* Output Descriptor */

#define DESCRIPTOR_KIND_BASE58    (0x0100 | DESCRIPTOR_KIND_ADDRESS)
#define DESCRIPTOR_KIND_BECH32    (0x0200 | DESCRIPTOR_KIND_ADDRESS)

#define DESCRIPTOR_KIND_PUBLIC_KEY          (0x001000 | DESCRIPTOR_KIND_KEY)
#define DESCRIPTOR_KIND_PRIVATE_KEY         (0x002000 | DESCRIPTOR_KIND_KEY)
#define DESCRIPTOR_KIND_BIP32               (0x004000 | DESCRIPTOR_KIND_KEY)
#define DESCRIPTOR_KIND_BIP32_PRIVATE_KEY   (0x010000 | DESCRIPTOR_KIND_BIP32)
#define DESCRIPTOR_KIND_BIP32_PUBLIC_KEY    (0x020000 | DESCRIPTOR_KIND_BIP32)

/* OP_0 properties: Bzudemsx */
#define PROP_OP_0  (TYPE_B | PROP_Z | PROP_U | PROP_D | PROP_E | PROP_M | PROP_S | PROP_X)
/* OP_1 properties: Bzufmx */
#define PROP_OP_1  (TYPE_B | PROP_Z | PROP_U | PROP_F | PROP_M | PROP_X)

#define DESCRIPTOR_LIMIT_LENGTH             1000000
#define DESCRIPTOR_BIP32_PATH_NUM_MAX       256
#define DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE   520
#define DESCRIPTOR_WITNESS_SCRIPT_MAX_SIZE  10000
#define DESCRIPTOR_MINISCRIPT_MUILTI_MAX    20
#define DESCRIPTOR_KEY_NAME_MAX_LENGTH      16
#define DESCRIPTOR_KEY_VALUE_MAX_LENGTH     130
#define DESCRIPTOR_NUMBER_BYTE_MAX_LENGTH   18
#define DESCRIPTOR_MIN_SIZE 20
#define XONLY_PUBLIC_KEY_LEN 32

#define DESCRIPTOR_CHECKSUM_LENGTH  8

/* output descriptor */
#define DESCRIPTOR_KIND_DESCRIPTOR_PK      (0x00000100 | DESCRIPTOR_KIND_DESCRIPTOR)
#define DESCRIPTOR_KIND_DESCRIPTOR_PKH     (0x00000200 | DESCRIPTOR_KIND_DESCRIPTOR)
#define DESCRIPTOR_KIND_DESCRIPTOR_MULTI   (0x00000300 | DESCRIPTOR_KIND_DESCRIPTOR)
#define DESCRIPTOR_KIND_DESCRIPTOR_MULTI_S (0x00000400 | DESCRIPTOR_KIND_DESCRIPTOR)
#define DESCRIPTOR_KIND_DESCRIPTOR_SH      (0x00000500 | DESCRIPTOR_KIND_DESCRIPTOR)
#define DESCRIPTOR_KIND_DESCRIPTOR_WPKH    (0x00010000 | DESCRIPTOR_KIND_DESCRIPTOR)
#define DESCRIPTOR_KIND_DESCRIPTOR_WSH     (0x00020000 | DESCRIPTOR_KIND_DESCRIPTOR)
#define DESCRIPTOR_KIND_DESCRIPTOR_COMBO   (0x00030000 | DESCRIPTOR_KIND_DESCRIPTOR)
#define DESCRIPTOR_KIND_DESCRIPTOR_ADDR    (0x00040000 | DESCRIPTOR_KIND_DESCRIPTOR)
#define DESCRIPTOR_KIND_DESCRIPTOR_RAW     (0x00050000 | DESCRIPTOR_KIND_DESCRIPTOR)
#define DESCRIPTOR_KIND_DESCRIPTOR_MASK    (0xffffff00 | DESCRIPTOR_KIND_DESCRIPTOR)

/* miniscript */
#define DESCRIPTOR_KIND_MINISCRIPT_PK        (0x00000100 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_PKH       (0x00000200 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_MULTI     (0x00000300 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_PK_K      (0x00001000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_PK_H      (0x00002000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_OLDER     (0x00010000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_AFTER     (0x00020000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_SHA256    (0x00030000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_HASH256   (0x00040000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_RIPEMD160 (0x00050000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_HASH160   (0x00060000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_THRESH    (0x00070000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_ANDOR     (0x01000000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_AND_V     (0x02000000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_AND_B     (0x03000000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_AND_N     (0x04000000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_OR_B      (0x05000000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_OR_C      (0x06000000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_OR_D      (0x07000000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_OR_I      (0x08000000 | DESCRIPTOR_KIND_MINISCRIPT)
#define DESCRIPTOR_KIND_MINISCRIPT_MASK      (0xffffff00 | DESCRIPTOR_KIND_MINISCRIPT)

/* Type */
struct miniscript_node_t;

typedef int (*wally_verify_descriptor_t)(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent);

typedef int (*wally_descriptor_to_script_t)(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len);

typedef int (*wally_miniscript_wrapper_to_script_t)(
    unsigned char *script,
    size_t script_len,
    size_t *write_len);

/* Struct */
struct wally_descriptor_script_item {
    unsigned char *script;
    size_t script_len;
    uint32_t child_num;
};

struct miniscript_item_t {
    const char *name;
    int kind;
    uint32_t type_properties;
    int inner_num;
    wally_verify_descriptor_t verify_function;
    wally_descriptor_to_script_t generate_function;
};

struct miniscript_node_t {
    const struct miniscript_item_t *info;
    struct miniscript_node_t *next;
    struct miniscript_node_t *back;
    struct miniscript_node_t *child;
    struct miniscript_node_t *parent;
    unsigned int chain_count;
    char wrapper_str[12];
    int kind;
    uint32_t type_properties;
    int64_t number;
    char *data;
    char *derive_path;
    char *key_origin_info;
    uint32_t data_size;
    uint32_t derive_path_len;
    uint32_t key_origin_info_len;
    uint32_t network_type;
    bool is_derive;
    bool is_uncompress_key;
    bool is_xonly_key;
};

struct multisig_sort_data_t {
    struct miniscript_node_t *node;
    unsigned char script[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    uint32_t script_size;
};

struct address_script_t {
    const unsigned char network;
    const unsigned char version_p2pkh;
    const unsigned char version_p2sh;
    const unsigned char version_wif;
    const char addr_family[8];
};

static const struct address_script_t g_network_addresses[] = {
    {
        WALLY_NETWORK_BITCOIN_MAINNET,
        WALLY_ADDRESS_VERSION_P2PKH_MAINNET,
        WALLY_ADDRESS_VERSION_P2SH_MAINNET,
        WALLY_ADDRESS_VERSION_WIF_MAINNET,
        { 'b', 'c', '\0', '\0', '\0', '\0', '\0', '\0' }
    },
    {
        WALLY_NETWORK_BITCOIN_TESTNET,
        WALLY_ADDRESS_VERSION_P2PKH_TESTNET,
        WALLY_ADDRESS_VERSION_P2SH_TESTNET,
        WALLY_ADDRESS_VERSION_WIF_TESTNET,
        { 't', 'b', '\0', '\0', '\0', '\0', '\0', '\0' }
    },
    {   /* Bitcoin regtest. This must remain immediately after WALLY_NETWORK_BITCOIN_TESTNET */
        WALLY_NETWORK_BITCOIN_REGTEST,
        WALLY_ADDRESS_VERSION_P2PKH_TESTNET,
        WALLY_ADDRESS_VERSION_P2SH_TESTNET,
        WALLY_ADDRESS_VERSION_WIF_TESTNET,
        { 'b', 'c', 'r', 't', '\0', '\0', '\0', '\0' }
    },
    {
        WALLY_NETWORK_LIQUID,
        WALLY_ADDRESS_VERSION_P2PKH_LIQUID,
        WALLY_ADDRESS_VERSION_P2SH_LIQUID,
        WALLY_ADDRESS_VERSION_WIF_MAINNET,
        { 'e', 'x', '\0', '\0', '\0', '\0', '\0', '\0' }
    },
    {
        WALLY_NETWORK_LIQUID_TESTNET,
        WALLY_ADDRESS_VERSION_P2PKH_LIQUID_TESTNET,
        WALLY_ADDRESS_VERSION_P2SH_LIQUID_TESTNET,
        WALLY_ADDRESS_VERSION_WIF_TESTNET,
        { 't', 'e', 'x', '\0', '\0', '\0', '\0', '\0' }
    },
    {
        WALLY_NETWORK_LIQUID_REGTEST,
        WALLY_ADDRESS_VERSION_P2PKH_LIQUID_REGTEST,
        WALLY_ADDRESS_VERSION_P2SH_LIQUID_REGTEST,
        WALLY_ADDRESS_VERSION_WIF_TESTNET,
        { 'e', 'r', 't', '\0', '\0', '\0', '\0', '\0' }
    },
};

#define NUM_NETWORK_ADDRESSES  (sizeof(g_network_addresses) / sizeof(g_network_addresses[0]))

static const struct address_script_t *netaddr_from_network(uint32_t network)
{
    size_t i;
    for (i = 0; i < NUM_NETWORK_ADDRESSES; ++i) {
        if (network == g_network_addresses[i].network)
            return g_network_addresses + i;
    }
    return NULL; /* Not found */
}

static const struct address_script_t *netaddr_from_addr_version(
    uint32_t addr_version, const struct address_script_t *target, bool *is_p2sh)
{
    size_t i;

    for (i = 0; i < NUM_NETWORK_ADDRESSES; ++i) {
        const struct address_script_t *netaddr = g_network_addresses + i;
        if (addr_version == netaddr->version_p2pkh || addr_version == netaddr->version_p2sh) {
            /* Found a matching network based on base58 address version*/
            if (target && netaddr->network != target->network) {
                /* Mismatch on caller provided network */
                if (netaddr->network == WALLY_NETWORK_BITCOIN_TESTNET && target->network == WALLY_NETWORK_BITCOIN_REGTEST) {
                    /* BTC testnet and regtest have the same versions; use the regtest entry */
                    ++netaddr;
                } else {
                    return NULL; /* Mismatch on provided network: Not found */
                }
            }
            *is_p2sh = addr_version == netaddr->version_p2sh;
            return netaddr; /* Found */
        }
    }
    return NULL; /* Not found */
}

static const struct address_script_t *netaddr_from_addr_family(const char *addr_family, uint32_t network)
{
    const struct address_script_t *netaddr = netaddr_from_network(network);
    if (!netaddr || strncmp(addr_family, netaddr->addr_family, sizeof(netaddr->addr_family)))
        return NULL; /* Not found or mismatched address version */
    return netaddr; /* Found */
}

/* Function prototype */
static int analyze_miniscript_addr(
    const char *message,
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent_node,
    const struct address_script_t *target_addr_item,
    unsigned char *script,
    size_t script_len,
    size_t *write_len);
static int generate_script_from_miniscript(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    uint32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len);
static int generate_script_from_number(
    int64_t number,
    struct miniscript_node_t *parent,
    unsigned char *script,
    size_t script_len,
    size_t *write_len);

/* Function */
static bool is_ascii_string(const char *message, size_t max_len)
{
    if (!message)
        return false;

    max_len += 1;
    while (*message && max_len--) {
        if (*message < ' ' || *message > '~')
            return false;
        ++message;
    }
    return max_len != 0;
}

static int realloc_substr_buffer(size_t need_len, char **buffer, size_t *buffer_len)
{
    size_t need_size = ((need_len / 64) + 2) * 64;
    if (!*buffer || need_size > *buffer_len) {
        if (*buffer)
            wally_free(*buffer);

        if (!(*buffer = wally_malloc(need_size)))
            return WALLY_ENOMEM;

        *buffer_len = need_size;
    }
    return WALLY_OK;
}

static int32_t get_child_list_count(struct miniscript_node_t *node)
{
    int32_t ret = 0;
    struct miniscript_node_t *chain = node->child;
    while (chain) {
        ++ret;
        chain = chain->next;
    }
    return ret;
}

static void free_miniscript_node(struct miniscript_node_t *node)
{
    if (!node)
        return;
    if (node->child) {
        struct miniscript_node_t *child = node->child;
        struct miniscript_node_t *next;
        while (child) {
            next = child->next;
            free_miniscript_node(child);
            child = next;
        }
    }

    clear_and_free(node->data, node->data_size);
    clear_and_free(node->derive_path, node->derive_path_len);
    clear_and_free(node->key_origin_info, node->key_origin_info_len);
    clear_and_free(node, sizeof(*node));
}

static int check_type_properties(uint32_t property)
{
    /* K, V, B, W all conflict with each other */
    switch (property & TYPE_MASK) {
    case TYPE_B:
    case TYPE_V:
    case TYPE_K:
    case TYPE_W:
        break;
    default:
        return WALLY_EINVAL;
    }

    if ((property & PROP_Z) && (property & PROP_O))
        return WALLY_EINVAL;
    if ((property & PROP_N) && (property & PROP_Z))
        return WALLY_EINVAL;
    if ((property & TYPE_V) && (property & PROP_D))
        return WALLY_EINVAL;
    if ((property & TYPE_K) && !(property & PROP_U))
        return WALLY_EINVAL;
    if ((property & TYPE_V) && (property & PROP_U))
        return WALLY_EINVAL;
    if ((property & PROP_E) && (property & PROP_F))
        return WALLY_EINVAL;
    if ((property & PROP_E) && !(property & PROP_D))
        return WALLY_EINVAL;
    if ((property & TYPE_V) && (property & PROP_E))
        return WALLY_EINVAL;
    if ((property & PROP_D) && (property & PROP_F))
        return WALLY_EINVAL;
    if ((property & TYPE_V) && !(property & PROP_F))
        return WALLY_EINVAL;
    if ((property & TYPE_K) && !(property & PROP_S))
        return WALLY_EINVAL;
    if ((property & PROP_Z) && !(property & PROP_M))
        return WALLY_EINVAL;

    return WALLY_OK;
}

static int verify_descriptor_sh(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    if (parent || (get_child_list_count(node) != node->info->inner_num) || !node->child->info)
        return WALLY_EINVAL;

    node->type_properties = node->child->type_properties;
    return WALLY_OK;
}

static bool has_uncompressed_key_by_child(struct miniscript_node_t *node)
{
    struct miniscript_node_t *child = node->child;
    while (child) {
        if (child->is_uncompress_key)
            return true;
        if (has_uncompressed_key_by_child(child))
            return true;

        child = child->next;
    }
    return false;
}

static int verify_descriptor_wsh(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    if (parent && (!parent->info || (parent->info->kind != DESCRIPTOR_KIND_DESCRIPTOR_SH)))
        return WALLY_EINVAL;
    if (get_child_list_count(node) != node->info->inner_num || !node->child->info)
        return WALLY_EINVAL;
    if (has_uncompressed_key_by_child(node))
        return WALLY_EINVAL;

    node->type_properties = node->child->type_properties;
    return WALLY_OK;
}

static int verify_descriptor_pk(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    (void)parent;
    if (get_child_list_count(node) != node->info->inner_num || node->child->info ||
        (node->child->kind & DESCRIPTOR_KIND_KEY) != DESCRIPTOR_KIND_KEY)
        return WALLY_EINVAL;

    node->type_properties = node->info->type_properties;
    return WALLY_OK;
}

static int verify_descriptor_pkh(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    return verify_descriptor_pk(node, parent);
}

static int verify_descriptor_wpkh(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    struct miniscript_node_t *parent_item = parent;
    if (parent && (!parent->info || (parent->info->kind & DESCRIPTOR_KIND_MINISCRIPT)))
        return WALLY_EINVAL;
    if (get_child_list_count(node) != node->info->inner_num || node->child->info ||
        (node->child->kind & DESCRIPTOR_KIND_KEY) != DESCRIPTOR_KIND_KEY)
        return WALLY_EINVAL;

    while (parent_item) {
        if (parent_item->kind == DESCRIPTOR_KIND_DESCRIPTOR_WSH)
            return WALLY_EINVAL;
        parent_item = parent_item->parent;
    }

    if (has_uncompressed_key_by_child(node))
        return WALLY_EINVAL;

    return WALLY_OK;
}

static int verify_descriptor_combo(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    if (parent)
        return WALLY_EINVAL;

    /* Since the combo is of multiple return types, the return value is wpkh or pkh. */
    if (has_uncompressed_key_by_child(node)) {
        return verify_descriptor_pkh(node, parent);
    } else {
        return verify_descriptor_wpkh(node, parent);
    }
}

static int verify_descriptor_multi(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    struct miniscript_node_t *top = NULL;
    struct miniscript_node_t *key = NULL;
    uint32_t require_num = 0;
    uint32_t count = (uint32_t) get_child_list_count(node);
    (void)parent;

    if (count < 2 || count - 1 > DESCRIPTOR_MINISCRIPT_MUILTI_MAX)
        return WALLY_EINVAL;

    top = node->child;
    require_num = (uint32_t) top->number;
    if (!top->next || top->info || (top->kind != DESCRIPTOR_KIND_NUMBER) ||
        (top->number <= 0) || (count < require_num))
        return WALLY_EINVAL;

    key = top->next;
    while (key) {
        if (key->info || !(key->kind & DESCRIPTOR_KIND_KEY))
            return WALLY_EINVAL;

        key = key->next;
    }

    node->type_properties = node->info->type_properties;
    return WALLY_OK;
}

static int verify_descriptor_sortedmulti(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    return verify_descriptor_multi(node, parent);
}

static int verify_descriptor_addr(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    if (parent || (get_child_list_count(node) != node->info->inner_num) || node->child->info ||
        (node->child->kind & DESCRIPTOR_KIND_ADDRESS) != DESCRIPTOR_KIND_ADDRESS)
        return WALLY_EINVAL;

    return WALLY_OK;
}

static int verify_descriptor_raw(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    if (parent || (get_child_list_count(node) != node->info->inner_num) || node->child->info ||
        (node->child->kind & DESCRIPTOR_KIND_RAW) == 0)
        return WALLY_EINVAL;

    return WALLY_OK;
}

static int verify_miniscript_pkh(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    (void)parent;
    if (get_child_list_count(node) != node->info->inner_num || node->child->info ||
        (node->child->kind & DESCRIPTOR_KIND_KEY) != DESCRIPTOR_KIND_KEY)
        return WALLY_EINVAL;

    node->type_properties = node->info->type_properties;
    return WALLY_OK;
}

static int verify_miniscript_pk(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    return verify_miniscript_pkh(node, parent);
}

static int verify_miniscript_older(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    (void)parent;
    if (get_child_list_count(node) != node->info->inner_num || node->child->info ||
        node->child->kind != DESCRIPTOR_KIND_NUMBER ||
        node->child->number <= 0 || node->child->number > 0x7fffffff)
        return WALLY_EINVAL;

    node->type_properties = node->info->type_properties;
    return WALLY_OK;
}

static int verify_miniscript_after(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    return verify_miniscript_older(node, parent);
}

static int verify_miniscript_hash_type(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    (void)parent;
    if (get_child_list_count(node) != node->info->inner_num || node->child->info ||
        (node->child->kind & DESCRIPTOR_KIND_RAW) == 0)
        return WALLY_EINVAL;

    node->type_properties = node->info->type_properties;
    return WALLY_OK;
}

static int verify_miniscript_sha256(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    return verify_miniscript_hash_type(node, parent);
}

static int verify_miniscript_hash256(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    return verify_miniscript_hash_type(node, parent);
}

static int verify_miniscript_ripemd160(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    return verify_miniscript_hash_type(node, parent);
}

static int verify_miniscript_hash160(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    return verify_miniscript_hash_type(node, parent);
}

static uint32_t verify_miniscript_andor_property(uint32_t x_property, uint32_t y_property, uint32_t z_property)
{
    /* Y and Z are both B, K, or V */
    uint32_t prop = PROP_X;
    uint32_t need_x = TYPE_B | PROP_D | PROP_U;
    uint32_t need_yz = TYPE_B | TYPE_K | TYPE_V;
    if (!(x_property & TYPE_B) || !(x_property & need_x))
        return 0;
    if (!(y_property & z_property & need_yz))
        return 0;

    prop |= y_property & z_property & need_yz;
    prop |= x_property & y_property & z_property & PROP_Z;
    prop |= (x_property | (y_property & z_property)) & PROP_O;
    prop |= y_property & z_property & PROP_U;
    prop |= z_property & PROP_D;
    if (x_property & PROP_S || y_property & PROP_F) {
        prop |= z_property & PROP_F;
        prop |= x_property & z_property & PROP_E;
    }
    if (x_property & PROP_E &&
        (x_property | y_property | z_property) & PROP_S) {
        prop |= x_property & y_property & z_property & PROP_M;
    }
    prop |= z_property & (x_property | y_property) & PROP_S;
    return prop;
}

static int verify_miniscript_andor(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    (void)parent;
    if (get_child_list_count(node) != node->info->inner_num)
        return WALLY_EINVAL;

    node->type_properties = verify_miniscript_andor_property(
        node->child->type_properties,
        node->child->next->type_properties,
        node->child->next->next->type_properties);
    if (!node->type_properties)
        return WALLY_EINVAL;

    return WALLY_OK;
}

static int verify_miniscript_two_param_check(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    (void)parent;
    if (get_child_list_count(node) != node->info->inner_num)
        return WALLY_EINVAL;

    return WALLY_OK;
}

static uint32_t verify_miniscript_and_v_property(uint32_t x_property, uint32_t y_property)
{
    uint32_t prop = 0;
    prop |= x_property & PROP_N;
    prop |= y_property & (PROP_U | PROP_X);
    prop |= x_property & y_property & (PROP_D | PROP_M | PROP_Z);
    prop |= (x_property | y_property) & PROP_S;
    if (x_property & TYPE_V)
        prop |= y_property & (TYPE_K | TYPE_V | TYPE_B);
    if (x_property & PROP_Z)
        prop |= y_property & PROP_N;
    if ((x_property | y_property) & PROP_Z)
        prop |= (x_property | y_property) & PROP_O;
    if (y_property & PROP_F || x_property & PROP_S)
        prop |= PROP_F;
    if (!(prop & TYPE_MASK))
        return 0;

    return prop;
}

static int verify_miniscript_and_v(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    int ret = verify_miniscript_two_param_check(node, parent);
    if (ret == WALLY_OK) {
        node->type_properties = verify_miniscript_and_v_property(
            node->child->type_properties,
            node->child->next->type_properties);
        if (!node->type_properties)
            ret = WALLY_EINVAL;
    }
    return ret;
}

static int verify_miniscript_and_b(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    uint32_t x_prop, y_prop;
    int ret = verify_miniscript_two_param_check(node, parent);
    if (ret != WALLY_OK)
        return ret;

    x_prop = node->child->type_properties;
    y_prop = node->child->next->type_properties;
    node->type_properties = PROP_U | PROP_X;
    node->type_properties |= x_prop & y_prop & (PROP_D | PROP_Z | PROP_M);
    node->type_properties |= (x_prop | y_prop) & PROP_S;
    node->type_properties |= x_prop & PROP_N;
    if (y_prop & TYPE_W)
        node->type_properties |= x_prop & TYPE_B;
    if ((x_prop | y_prop) & PROP_Z)
        node->type_properties |= (x_prop | y_prop) & PROP_O;
    if (x_prop & PROP_Z)
        node->type_properties |= y_prop & PROP_N;
    if ((x_prop & y_prop) & PROP_S)
        node->type_properties |= x_prop & y_prop & PROP_E;
    if (((x_prop & y_prop) & PROP_F) ||
        !(~x_prop & (PROP_S | PROP_F)) ||
        !(~y_prop & (PROP_S | PROP_F)))
        node->type_properties |= PROP_F;

    return WALLY_OK;
}

static int verify_miniscript_and_n(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    int ret = verify_miniscript_two_param_check(node, parent);
    if (ret == WALLY_OK) {
        node->type_properties = verify_miniscript_andor_property(
            node->child->type_properties,
            node->child->next->type_properties,
            PROP_OP_0);
        if (!node->type_properties)
            ret = WALLY_EINVAL;
    }
    return ret;
}

static int verify_miniscript_or_b(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    uint32_t x_prop, y_prop;
    int ret = verify_miniscript_two_param_check(node, parent);
    if (ret != WALLY_OK)
        return ret;

    x_prop = node->child->type_properties;
    y_prop = node->child->next->type_properties;
    node->type_properties = PROP_D | PROP_U | PROP_X;
    node->type_properties |= x_prop & y_prop & (PROP_Z | PROP_S | PROP_E);
    if (!(~x_prop & (TYPE_B | PROP_D)) &&
        !(~y_prop & (TYPE_W | PROP_D)))
        node->type_properties |= TYPE_B;
    if ((x_prop | y_prop) & PROP_Z)
        node->type_properties |= (x_prop | y_prop) & PROP_O;
    if (((x_prop | y_prop) & PROP_S) &&
        ((x_prop & y_prop) & PROP_E))
        node->type_properties |= x_prop & y_prop & PROP_M;

    return WALLY_OK;
}

static int verify_miniscript_or_c(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    uint32_t x_prop, y_prop;
    int ret = verify_miniscript_two_param_check(node, parent);
    if (ret != WALLY_OK)
        return ret;

    x_prop = node->child->type_properties;
    y_prop = node->child->next->type_properties;
    node->type_properties = PROP_F | PROP_X;
    node->type_properties |= x_prop & y_prop & (PROP_Z | PROP_S);
    if (!(~x_prop & (TYPE_B | PROP_D | PROP_U)))
        node->type_properties |= y_prop & TYPE_V;
    if (y_prop & PROP_Z)
        node->type_properties |= x_prop & PROP_O;
    if (x_prop & PROP_E && ((x_prop | y_prop) & PROP_S))
        node->type_properties |= x_prop & y_prop & PROP_M;

    return ret;
}

static int verify_miniscript_or_d(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    uint32_t x_prop, y_prop;
    int ret = verify_miniscript_two_param_check(node, parent);
    if (ret != WALLY_OK)
        return ret;

    x_prop = node->child->type_properties;
    y_prop = node->child->next->type_properties;
    node->type_properties = PROP_X;
    node->type_properties |= x_prop & y_prop & (PROP_Z | PROP_E | PROP_S);
    node->type_properties |= y_prop & (PROP_U | PROP_F | PROP_D);
    if (!(~x_prop & (TYPE_B | PROP_D | PROP_U)))
        node->type_properties |= y_prop & TYPE_B;
    if (y_prop & PROP_Z)
        node->type_properties |= x_prop & PROP_O;
    if (x_prop & PROP_E && ((x_prop | y_prop) & PROP_S))
        node->type_properties |= x_prop & y_prop & PROP_M;

    return WALLY_OK;
}

static uint32_t verify_miniscript_or_i_property(uint32_t x_property, uint32_t y_property)
{
    uint32_t prop = PROP_X;
    prop |= x_property & y_property & (TYPE_V | TYPE_B | TYPE_K | PROP_U | PROP_F | PROP_S);
    if (!(prop & TYPE_MASK))
        return 0;

    prop |= (x_property | y_property) & PROP_D;
    if ((x_property & y_property) & PROP_Z)
        prop |= PROP_O;
    if ((x_property | y_property) & PROP_F)
        prop |= (x_property | y_property) & PROP_E;
    if ((x_property | y_property) & PROP_S)
        prop |= x_property & y_property & PROP_M;

    return prop;
}

static int verify_miniscript_or_i(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    int ret = verify_miniscript_two_param_check(node, parent);
    if (ret == WALLY_OK) {
        node->type_properties = verify_miniscript_or_i_property(
            node->child->type_properties,
            node->child->next->type_properties);
        if (!node->type_properties)
            ret = WALLY_EINVAL;
    }
    return ret;
}

static int verify_miniscript_thresh(struct miniscript_node_t *node, struct miniscript_node_t *parent)
{
    struct miniscript_node_t *top = NULL;
    struct miniscript_node_t *child = NULL;
    uint32_t count = 0;
    uint32_t k = 0;
    bool all_e = true;
    bool all_m = true;
    uint32_t args = 0;
    uint32_t num_s = 0;
    (void)parent;

    if (get_child_list_count(node) < 4)
        return WALLY_EINVAL;

    top = node->child;
    if (top->info || (top->kind != DESCRIPTOR_KIND_NUMBER) || (top->number < 0))
        return WALLY_EINVAL;

    k = (uint32_t) top->number;
    if (k < 1)
        return WALLY_EINVAL;

    child = top->next;
    while (child) {
        if (!child->info)
            return WALLY_EINVAL;

        if (!count) {
            if (~(child->type_properties) & (TYPE_B | PROP_D | PROP_U))
                return WALLY_EINVAL;
        } else if (~(child->type_properties) & (TYPE_W | PROP_D | PROP_U))
            return WALLY_EINVAL;

        if (~(child->type_properties) & PROP_E)
            all_e = false;
        if (~(child->type_properties) & PROP_M)
            all_m = false;
        if (child->type_properties & PROP_S)
            ++num_s;
        if (child->type_properties & PROP_Z)
            args += (~(child->type_properties) & PROP_O) ? 2 : 1;

        ++count;
        child = child->next;
    }

    if (k > count)
        return WALLY_EINVAL;

    node->type_properties = TYPE_B | PROP_D | PROP_U;
    if (args == 0)
        node->type_properties |= PROP_Z;
    else if (args == 1)
        node->type_properties |= PROP_O;
    if (all_e && num_s == count)
        node->type_properties |= PROP_E;
    if (all_e && all_m && num_s >= count - k)
        node->type_properties |= PROP_M;
    if (num_s >= count - k + 1)
        node->type_properties |= PROP_S;

    return WALLY_OK;
}

static int verify_miniscript_wrappers(struct miniscript_node_t *node)
{
    size_t i;

    if (node->wrapper_str[0] == '\0')
        return WALLY_OK; /* No wrappers */

    /* Validate the nodes wrappers in reserve order */
    for (i = strlen(node->wrapper_str); i != 0; --i) {
        const uint32_t x_prop = node->type_properties;
#define PROP_REQUIRE(props) if ((x_prop & (props)) != (props)) return WALLY_EINVAL
#define PROP_CHANGE_TYPE(clr, set) node->type_properties &= ~(clr); node->type_properties |= set
#define PROP_CHANGE(keep, set) node->type_properties &= (TYPE_MASK | keep); node->type_properties |= set

        switch(node->wrapper_str[i - 1]) {
        case 'a':
            PROP_REQUIRE(TYPE_B);
            PROP_CHANGE_TYPE(TYPE_B, TYPE_W);
            PROP_CHANGE(PROP_U | PROP_D | PROP_F | PROP_E | PROP_M | PROP_S, PROP_X);
            break;
        case 's':
            PROP_REQUIRE(TYPE_B | PROP_O);
            PROP_CHANGE_TYPE(TYPE_B | PROP_O, TYPE_W);
            PROP_CHANGE(PROP_U | PROP_D | PROP_F | PROP_E | PROP_M | PROP_S | PROP_X, 0);
            break;
        case 'c':
            PROP_REQUIRE(TYPE_K);
            PROP_CHANGE_TYPE(TYPE_K, TYPE_B);
            PROP_CHANGE(PROP_O | PROP_N | PROP_D | PROP_F | PROP_E | PROP_M, PROP_U | PROP_S);
            break;
        case 't':
            node->type_properties = verify_miniscript_and_v_property(x_prop, PROP_OP_1);
            if (!(node->type_properties & TYPE_MASK))
                return WALLY_EINVAL;
            /* prop >= PROP_F */
            break;
        case 'd':
            PROP_REQUIRE(TYPE_V | PROP_Z);
            PROP_CHANGE_TYPE(TYPE_V | PROP_Z, TYPE_B);
            PROP_CHANGE(PROP_M | PROP_S, PROP_N | PROP_U | PROP_D | PROP_X);
            if (x_prop & PROP_Z)
                node->type_properties |= PROP_O;
            if (x_prop & PROP_F) {
                node->type_properties &= ~PROP_F;
                node->type_properties |= PROP_E;
            }
            break;
        case 'v':
            PROP_REQUIRE(TYPE_B);
            PROP_CHANGE_TYPE(TYPE_B, TYPE_V);
            PROP_CHANGE(PROP_Z | PROP_O | PROP_N | PROP_M | PROP_S, PROP_F | PROP_X);
            break;
        case 'j':
            PROP_REQUIRE(TYPE_B | PROP_N);
            node->type_properties &= TYPE_MASK | PROP_O | PROP_U | PROP_M | PROP_S;
            node->type_properties |= PROP_N | PROP_D | PROP_X;
            if (x_prop & PROP_F) {
                PROP_CHANGE(~PROP_F, PROP_E);
            }
            break;
        case 'n':
            PROP_REQUIRE(TYPE_B);
            PROP_CHANGE(PROP_Z | PROP_O | PROP_N | PROP_D | PROP_F | PROP_E | PROP_M | PROP_S, PROP_X);
            break;
        case 'l':
            node->type_properties = verify_miniscript_or_i_property(PROP_OP_0, x_prop);
            if (!node->type_properties)
                return WALLY_EINVAL;
            break;
        case 'u':
            node->type_properties = verify_miniscript_or_i_property(x_prop, PROP_OP_0);
            if (!node->type_properties)
                return WALLY_EINVAL;
            break;
        default:
            return WALLY_EINVAL;     /* Wrapper type not found */
            break;
        }
    }

    return check_type_properties(node->type_properties);
}

static int generate_by_miniscript_pk_k(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;

    if (!node->child || (script_len < EC_PUBLIC_KEY_LEN * 2) || (parent && !parent->info))
        return WALLY_EINVAL;

    ret = generate_script_from_miniscript(node->child, node, child_num, &script[1], script_len - 1, write_len);
    if (ret != WALLY_OK)
        return ret;

    if (*write_len + 1 > DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE)
        return WALLY_EINVAL;

    script[0] = (unsigned char)*write_len;
    ++(*write_len);
    return ret;
}

static int generate_by_miniscript_pk_h(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    size_t child_write_len = *write_len;
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];

    if (!node->child || (script_len < WALLY_SCRIPTPUBKEY_P2PKH_LEN - 1) || (parent && !parent->info))
        return WALLY_EINVAL;
    if (node->child->is_xonly_key)
        return WALLY_EINVAL;

    ret = generate_script_from_miniscript(node->child, node, child_num, pubkey, sizeof(pubkey), &child_write_len);
    if (ret != WALLY_OK)
        return ret;

    ret = wally_hash160(pubkey, child_write_len, &script[3], HASH160_LEN);
    if (ret != WALLY_OK)
        return ret;

    script[0] = OP_DUP;
    script[1] = OP_HASH160;
    script[2] = HASH160_LEN;
    script[HASH160_LEN + 3] = OP_EQUALVERIFY;
    *write_len = HASH160_LEN + 4;
    return ret;
}

static int generate_by_descriptor_sh(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    size_t child_write_len = *write_len;
    unsigned char buf[WALLY_SCRIPTPUBKEY_P2SH_LEN];
    if (!node->child || (script_len < WALLY_SCRIPTPUBKEY_P2SH_LEN) || (parent && !parent->info))
        return WALLY_EINVAL;

    ret = generate_script_from_miniscript(node->child, node, child_num, script, script_len, &child_write_len);
    if (ret != WALLY_OK)
        return ret;

    if (child_write_len > DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE)
        return WALLY_EINVAL;

    ret = wally_scriptpubkey_p2sh_from_bytes(script, child_write_len, WALLY_SCRIPT_HASH160, buf, WALLY_SCRIPTPUBKEY_P2SH_LEN, write_len);
    if (ret == WALLY_OK)
        memcpy(script, buf, *write_len);

    return ret;
}

static int generate_by_descriptor_wsh(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    size_t child_write_len = *write_len;
    unsigned char output[WALLY_SCRIPTPUBKEY_P2WSH_LEN];

    if (!node->child || (script_len < sizeof(output)) || (parent && !parent->info))
        return WALLY_EINVAL;

    ret = generate_script_from_miniscript(node->child, node, child_num, script, script_len, &child_write_len);
    if (ret != WALLY_OK)
        return ret;

    if (child_write_len > DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE)
        return WALLY_EINVAL;

    ret = wally_witness_program_from_bytes(script, child_write_len, WALLY_SCRIPT_SHA256, output, WALLY_SCRIPTPUBKEY_P2WSH_LEN, write_len);
    if (ret == WALLY_OK)
        memcpy(script, output, *write_len);

    return ret;
}

static int generate_checksig(unsigned char *script, size_t script_len, size_t *write_len)
{
    size_t used_len = *write_len;
    if (!used_len || (used_len + 1 > script_len) || (used_len + 1 > DESCRIPTOR_WITNESS_SCRIPT_MAX_SIZE))
        return WALLY_EINVAL;

    script[used_len] = OP_CHECKSIG;
    *write_len = used_len + 1;
    return WALLY_OK;
}

static int generate_by_descriptor_pk(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret = generate_by_miniscript_pk_k(node, parent, child_num, script, script_len, write_len);
    return ret == WALLY_OK ? generate_checksig(script, script_len, write_len) : ret;
}

static int generate_by_descriptor_pkh(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;

    if (script_len < WALLY_SCRIPTPUBKEY_P2PKH_LEN)
        return WALLY_EINVAL;

    ret = generate_by_miniscript_pk_h(node, parent, child_num, script, script_len, write_len);
    return ret == WALLY_OK ? generate_checksig(script, script_len, write_len) : ret;
}

static int generate_by_descriptor_wpkh(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    size_t child_write_len = *write_len;
    unsigned char output[WALLY_SCRIPTPUBKEY_P2WPKH_LEN];

    if (!node->child || (script_len < sizeof(output)) || (parent && !parent->info))
        return WALLY_EINVAL;

    ret = generate_script_from_miniscript(node->child, node, child_num, script, script_len, &child_write_len);
    if (ret != WALLY_OK)
        return ret;

    if (child_write_len > DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE)
        return WALLY_EINVAL;

    ret = wally_witness_program_from_bytes(script, child_write_len, WALLY_SCRIPT_HASH160, output, WALLY_SCRIPTPUBKEY_P2WPKH_LEN, write_len);
    if (ret == WALLY_OK)
        memcpy(script, output, *write_len);

    return ret;
}

static int generate_by_descriptor_combo(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    if (has_uncompressed_key_by_child(node))
        return generate_by_descriptor_pkh(node, parent, child_num, script, script_len, write_len);
    return generate_by_descriptor_wpkh(node, parent, child_num, script, script_len, write_len);
}

static int compare_multisig_node(const void *source, const void *destination)
{
    const struct multisig_sort_data_t *src = (const struct multisig_sort_data_t *)source;
    const struct multisig_sort_data_t *dest = (const struct multisig_sort_data_t *)destination;
    uint32_t index = 0;
    if (src->script_size != dest->script_size) {
        /* Head byte of compressed pubkey and uncompressed pubkey are different. */
        return (int)src->script[0] - (int)dest->script[0];
    }

    for (; index < src->script_size; ++index) {
        if (src->script[index] != dest->script[index]) {
            return (int)src->script[index] - (int)dest->script[index];
        }
    }
    return 0;
}

static int generate_by_descriptor_multisig(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    int flag,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    size_t child_write_len = 0;
    size_t offset;
    uint32_t count = 0;
    uint32_t index = 0;
    struct miniscript_node_t *child = node->child;
    struct miniscript_node_t *temp_node;
    struct multisig_sort_data_t *sorted_node_array;
    size_t check_len = (DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE > script_len) ? script_len : DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE;

    if (!child || (parent && !parent->info))
        return WALLY_EINVAL;

    ret = generate_script_from_miniscript(child, node, child_num, script, script_len, &offset);
    if (ret != WALLY_OK)
        return ret;

    temp_node = child->next;
    while (temp_node) {
        ++count;
        temp_node = temp_node->next;
    }

    if (!(sorted_node_array = wally_malloc(count * sizeof(*sorted_node_array))))
        return WALLY_ENOMEM;

    temp_node = child->next;
    while (temp_node) {
        sorted_node_array[index].node = temp_node;
        ++index;
        temp_node = temp_node->next;
    }

    if (ret == WALLY_OK) {
        for (index = 0; index < count; ++index) {
            child_write_len = 0;
            ret = generate_script_from_miniscript(
                sorted_node_array[index].node, node, child_num,
                sorted_node_array[index].script,
                sizeof(sorted_node_array[index].script),
                &child_write_len);
            if (ret != WALLY_OK)
                break;
            sorted_node_array[index].script_size = (uint32_t)child_write_len;
        }
    }
    if (ret == WALLY_OK) {
        if (flag == WALLY_SCRIPT_MULTISIG_SORTED) {
            qsort(sorted_node_array, count, sizeof(struct multisig_sort_data_t),
                  compare_multisig_node);
        }
        for (index = 0; index < count; ++index) {
            if (offset + sorted_node_array[index].script_size + 1 > check_len) {
                ret = WALLY_EINVAL;
                break;
            }

            memcpy(&script[offset + 1], sorted_node_array[index].script,
                   sorted_node_array[index].script_size);
            script[offset] = (unsigned char) sorted_node_array[index].script_size;
            offset += sorted_node_array[index].script_size + 1;
        }
    }

    if (ret == WALLY_OK) {
        ret = generate_script_from_number((int64_t)count, parent, &script[offset],
                                          check_len - offset, &child_write_len);
    }

    if (ret == WALLY_OK) {
        offset += child_write_len;
        if (offset + 1 > check_len) {
            ret = WALLY_EINVAL;
        } else {
            script[offset] = OP_CHECKMULTISIG;
            *write_len = offset + 1;
        }
    }
    wally_free(sorted_node_array);
    return WALLY_OK;
}

static int generate_by_descriptor_multi(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    return generate_by_descriptor_multisig(
        node, parent, child_num, 0, script, script_len, write_len);
}

static int generate_by_descriptor_sorted_multi(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    return generate_by_descriptor_multisig(node, parent, child_num,
                                           WALLY_SCRIPT_MULTISIG_SORTED,
                                           script, script_len, write_len);
}


static int generate_by_descriptor_addr(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    if (!node->child || (script_len == 0) || (parent && !parent->info))
        return WALLY_EINVAL;

    ret = generate_script_from_miniscript(
        node->child, node, child_num, script, script_len, write_len);
    if (*write_len > DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE)
        return WALLY_EINVAL;

    return ret;
}

static int generate_by_descriptor_raw(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    if (!node->child || (script_len == 0) || (parent && !parent->info))
        return WALLY_EINVAL;

    ret = generate_script_from_miniscript(
        node->child, node, child_num, script, script_len, write_len);
    if (*write_len > DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE)
        return WALLY_EINVAL;

    return ret;
}

static int generate_by_miniscript_older(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    size_t child_write_len = *write_len;
    if (!node->child || (script_len < DESCRIPTOR_MIN_SIZE) || (parent && !parent->info))
        return WALLY_EINVAL;

    ret = generate_script_from_miniscript(
        node->child, node, child_num, script, script_len, &child_write_len);
    if (ret != WALLY_OK)
        return ret;

    if (child_write_len + 1 > DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE)
        return WALLY_EINVAL;

    script[child_write_len] = OP_CHECKSEQUENCEVERIFY;
    *write_len = child_write_len + 1;
    return ret;
}

static int generate_by_miniscript_after(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    size_t child_write_len = *write_len;
    if (!node->child || (script_len < DESCRIPTOR_MIN_SIZE) || (parent && !parent->info))
        return WALLY_EINVAL;

    ret = generate_script_from_miniscript(
        node->child, node, child_num, script, script_len, &child_write_len);
    if (ret != WALLY_OK)
        return ret;

    if (child_write_len + 1 > DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE)
        return WALLY_EINVAL;

    script[child_write_len] = OP_CHECKLOCKTIMEVERIFY;
    *write_len = child_write_len + 1;
    return ret;
}

static int generate_by_miniscript_crypto(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char crypto_op_code,
    unsigned char crypto_size,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    size_t child_write_len = *write_len;
    size_t check_len = (DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE > script_len) ?
                       script_len : DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE;

    if (!node->child || (script_len < (size_t)(crypto_size + 8)) || (parent && !parent->info))
        return WALLY_EINVAL;

    ret = generate_script_from_miniscript(node->child, node, child_num,
                                          &script[6], script_len - 8, &child_write_len);
    if (ret != WALLY_OK)
        return ret;

    if (child_write_len + 7 > check_len)
        return WALLY_EINVAL;

    script[0] = OP_SIZE;
    script[1] = 0x01;
    script[2] = 0x20;
    script[3] = OP_EQUALVERIFY;
    script[4] = crypto_op_code;
    script[5] = crypto_size;
    script[child_write_len + 6] = OP_EQUAL;
    *write_len = child_write_len + 7;
    return ret;
}

static int generate_by_miniscript_sha256(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    return generate_by_miniscript_crypto(node, parent, child_num, OP_SHA256, SHA256_LEN,
                                         script, script_len, write_len);
}

static int generate_by_miniscript_hash256(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    return generate_by_miniscript_crypto(node, parent, child_num, OP_HASH256, SHA256_LEN,
                                         script, script_len, write_len);
}

static int generate_by_miniscript_ripemd160(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    return generate_by_miniscript_crypto(node, parent, child_num, OP_RIPEMD160,
                                         HASH160_LEN, script, script_len, write_len);
}

static int generate_by_miniscript_hash160(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    return generate_by_miniscript_crypto(node, parent, child_num, OP_HASH160, HASH160_LEN,
                                         script, script_len, write_len);
}

static int generate_by_miniscript_concat(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    size_t target_num,
    const size_t *reference_indexes,
    unsigned char *prev_insert,
    size_t prev_insert_num,
    unsigned char *first_insert,
    size_t first_insert_num,
    unsigned char *second_insert,
    size_t second_insert_num,
    unsigned char *last_append,
    size_t last_append_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    size_t output_len;
    size_t total = prev_insert_num + first_insert_num + second_insert_num;
    size_t index = 0;
    size_t offset = 0;
    struct miniscript_node_t *child[3] = { NULL, NULL, NULL };
    size_t default_indexes[] = {0, 1, 2};
    const size_t *indexes = reference_indexes;
    size_t check_len = (DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE > script_len) ?
                       script_len : DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE;

    if (!node->child || (parent && !parent->info))
        return WALLY_EINVAL;

    if (!reference_indexes)
        indexes = default_indexes;

    for (index = 0; index < target_num; ++index) {
        child[index] = (index == 0) ? node->child : child[index - 1]->next;
        if (!child[index])
            return WALLY_EINVAL;
    }

    for (index = 0; index < target_num; ++index) {
        if (index == 0 && prev_insert_num) {
            memcpy(script + offset, prev_insert, prev_insert_num);
            offset += prev_insert_num;
        }
        if (index == 1 && first_insert_num) {
            memcpy(script + offset, first_insert, first_insert_num);
            offset += first_insert_num;
        }
        if (index == 2 && second_insert_num) {
            memcpy(script + offset, second_insert, second_insert_num);
            offset += second_insert_num;
        }

        output_len = 0;
        ret = generate_script_from_miniscript(child[indexes[index]], node, child_num,
                                              &script[offset], script_len - offset - 1,
                                              &output_len);
        if (ret != WALLY_OK)
            return ret;

        offset += output_len;
        total += output_len;
        if (total > check_len)
            return WALLY_EINVAL;
    }

    if (total + last_append_num > check_len)
        return WALLY_EINVAL;
    if (last_append_num) {
        memcpy(script + offset, last_append, last_append_num);
        offset += last_append_num;
    }

    if (ret == WALLY_OK)
        *write_len = offset;

    return ret;
}

static int generate_by_miniscript_andor(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    unsigned char first_op[] = {OP_NOTIF};
    unsigned char second_op[] = {OP_ELSE};
    unsigned char last_op[] = {OP_ENDIF};
    const size_t indexes[] = {0, 2, 1};
    /* [X] NOTIF 0 ELSE [Y] ENDIF */
    return generate_by_miniscript_concat(
        node,
        parent,
        child_num,
        3,
        indexes,
        NULL,
        0,
        first_op,
        sizeof(first_op) / sizeof(unsigned char),
        second_op,
        sizeof(second_op) / sizeof(unsigned char),
        last_op,
        sizeof(last_op) / sizeof(unsigned char),
        script,
        script_len,
        write_len);
}

static int generate_by_miniscript_and_v(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    /* [X] [Y] */
    const size_t indexes[] = {0, 1};
    return generate_by_miniscript_concat(
        node,
        parent,
        child_num,
        2,
        indexes,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0,
        script,
        script_len,
        write_len);
}

static int generate_by_miniscript_and_b(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    unsigned char append = OP_BOOLAND;
    const size_t indexes[] = {0, 1};
    /* [X] [Y] BOOLAND */
    return generate_by_miniscript_concat(
        node,
        parent,
        child_num,
        2,
        indexes,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0,
        &append,
        1,
        script,
        script_len,
        write_len);
}

static int generate_by_miniscript_and_n(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    unsigned char middle_op[] = {OP_NOTIF, OP_0, OP_ELSE};
    unsigned char last_op[] = {OP_ENDIF};
    const size_t indexes[] = {0, 1};
    /* [X] NOTIF 0 ELSE [Y] ENDIF */
    return generate_by_miniscript_concat(
        node,
        parent,
        child_num,
        2,
        indexes,
        NULL,
        0,
        middle_op,
        sizeof(middle_op) / sizeof(unsigned char),
        NULL,
        0,
        last_op,
        sizeof(last_op) / sizeof(unsigned char),
        script,
        script_len,
        write_len);
}

static int generate_by_miniscript_or_b(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    unsigned char append = OP_BOOLOR;
    const size_t indexes[] = {0, 1};
    /* [X] [Y] OP_BOOLOR */
    return generate_by_miniscript_concat(
        node,
        parent,
        child_num,
        2,
        indexes,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0,
        &append,
        1,
        script,
        script_len,
        write_len);
}

static int generate_by_miniscript_or_c(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    unsigned char middle_op[] = {OP_NOTIF};
    unsigned char last_op[] = {OP_ENDIF};
    const size_t indexes[] = {0, 1};
    /* [X] NOTIF [Z] ENDIF */
    return generate_by_miniscript_concat(
        node,
        parent,
        child_num,
        2,
        indexes,
        NULL,
        0,
        middle_op,
        sizeof(middle_op) / sizeof(unsigned char),
        NULL,
        0,
        last_op,
        sizeof(last_op) / sizeof(unsigned char),
        script,
        script_len,
        write_len);
}

static int generate_by_miniscript_or_d(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    unsigned char middle_op[] = {OP_IFDUP, OP_NOTIF};
    unsigned char last_op[] = {OP_ENDIF};
    const size_t indexes[] = {0, 1};
    /* [X] IFDUP NOTIF [Z] ENDIF */
    return generate_by_miniscript_concat(
        node,
        parent,
        child_num,
        2,
        indexes,
        NULL,
        0,
        middle_op,
        sizeof(middle_op) / sizeof(unsigned char),
        NULL,
        0,
        last_op,
        sizeof(last_op) / sizeof(unsigned char),
        script,
        script_len,
        write_len);
}

static int generate_by_miniscript_or_i(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    unsigned char top_op[] = {OP_IF};
    unsigned char middle_op[] = {OP_ELSE};
    unsigned char last_op[] = {OP_ENDIF};
    const size_t indexes[] = {0, 1};
    /* IF [X] ELSE [Z] ENDIF */
    return generate_by_miniscript_concat(
        node,
        parent,
        child_num,
        2,
        indexes,
        top_op,
        sizeof(top_op) / sizeof(unsigned char),
        middle_op,
        sizeof(middle_op) / sizeof(unsigned char),
        NULL,
        0,
        last_op,
        sizeof(last_op) / sizeof(unsigned char),
        script,
        script_len,
        write_len);
}

static int generate_by_miniscript_thresh(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    int32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    /* [X1] [X2] ADD ... [Xn] ADD <k> EQUAL */
    int ret;
    size_t output_len;
    size_t offset = 0;
    size_t count = 0;
    struct miniscript_node_t *child = node->child;
    size_t check_len = (DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE > script_len) ? script_len : DESCRIPTOR_REDEEM_SCRIPT_MAX_SIZE;

    if (!child || (parent && !parent->info))
        return WALLY_EINVAL;

    child = child->next;
    while (child) {
        output_len = 0;
        ret = generate_script_from_miniscript(child,
                                              node,
                                              child_num,
                                              &script[offset],
                                              script_len - offset - 1,
                                              &output_len);
        if (ret != WALLY_OK)
            return ret;

        ++count;
        offset += output_len;
        if (offset >= check_len)
            return WALLY_EINVAL;

        if (count != 1) {
            if (offset + 1 >= check_len)
                return WALLY_EINVAL;

            script[offset] = OP_ADD;
            ++offset;
        }

        child = child->next;
    }

    ret = generate_script_from_miniscript(node->child,
                                          node,
                                          child_num,
                                          &script[offset],
                                          script_len - offset - 1,
                                          &output_len);
    if (ret != WALLY_OK)
        return ret;

    offset += output_len;
    if (offset + 1 >= check_len)
        return WALLY_EINVAL;

    script[offset] = OP_EQUAL;
    *write_len = offset + 1;
    return WALLY_OK;
}

static int generate_miniscript_wrappers(struct miniscript_node_t *node,
                                        unsigned char *script, size_t script_len, size_t *write_len)
{
    size_t i;

    if (node->wrapper_str[0] == '\0')
        return WALLY_OK; /* No wrappers */

    if (!*write_len)
        return WALLY_EINVAL; /* Nothing to wrap */

    /* Validate the nodes wrappers in reserve order */
    for (i = strlen(node->wrapper_str); i != 0; --i) {
        size_t used_len = *write_len;

        switch(node->wrapper_str[i - 1]) {
        case 'a':
            if (used_len + 2 > script_len || used_len + 2 > DESCRIPTOR_WITNESS_SCRIPT_MAX_SIZE)
                return WALLY_EINVAL;

            memmove(script + 1, script, used_len);
            script[0] = OP_TOALTSTACK;
            script[used_len + 1] = OP_FROMALTSTACK;
            *write_len = used_len + 2;
            break;

        case 's':
            if (used_len + 1 > script_len || used_len + 1 > DESCRIPTOR_WITNESS_SCRIPT_MAX_SIZE)
                return WALLY_EINVAL;

            memmove(script + 1, script, used_len);
            script[0] = OP_SWAP;
            *write_len = used_len + 1;
            break;

        case 'c':
            if (used_len + 1 > script_len || used_len + 1 > DESCRIPTOR_WITNESS_SCRIPT_MAX_SIZE)
                return WALLY_EINVAL;

            script[used_len] = OP_CHECKSIG;
            *write_len = used_len + 1;
            break;

        case 't':
            if (used_len + 1 > script_len || used_len + 1 > DESCRIPTOR_WITNESS_SCRIPT_MAX_SIZE)
                return WALLY_EINVAL;

            script[used_len] = OP_1;
            *write_len = used_len + 1;
            break;

        case 'd':
            if (used_len + 3 > script_len || used_len + 3 > DESCRIPTOR_WITNESS_SCRIPT_MAX_SIZE)
                return WALLY_EINVAL;

            memmove(script + 2, script, used_len);
            script[0] = OP_DUP;
            script[1] = OP_IF;
            script[used_len + 2] = OP_ENDIF;
            *write_len = used_len + 3;
            break;

        case 'v':

            if (script[used_len - 1] == OP_EQUAL) {
                script[used_len - 1] = OP_EQUALVERIFY;
            } else if (script[used_len - 1] == OP_NUMEQUAL) {
                script[used_len - 1] = OP_NUMEQUALVERIFY;
            } else if (script[used_len - 1] == OP_CHECKSIG) {
                script[used_len - 1] = OP_CHECKSIGVERIFY;
            } else if (script[used_len - 1] == OP_CHECKMULTISIG) {
                script[used_len - 1] = OP_CHECKMULTISIGVERIFY;
            } else if (script[used_len - 1] == OP_CHECKMULTISIG) {
                script[used_len - 1] = OP_CHECKMULTISIGVERIFY;
            } else {
                if (used_len + 1 > script_len)
                    return WALLY_EINVAL;
                script[used_len] = OP_VERIFY;
                *write_len = used_len + 1;
                if (*write_len > DESCRIPTOR_WITNESS_SCRIPT_MAX_SIZE)
                    return WALLY_EINVAL;
            }
            break;

        case 'j':
            if (used_len + 4 > script_len || used_len + 4 > DESCRIPTOR_WITNESS_SCRIPT_MAX_SIZE)
                return WALLY_EINVAL;

            memmove(script + 3, script, used_len);
            script[0] = OP_SIZE;
            script[1] = OP_0NOTEQUAL;
            script[2] = OP_IF;
            script[used_len + 3] = OP_ENDIF;
            *write_len = used_len + 4;
            break;

        case 'n':
            if (used_len + 1 > script_len || used_len + 1 > DESCRIPTOR_WITNESS_SCRIPT_MAX_SIZE)
                return WALLY_EINVAL;

            script[used_len] = OP_0NOTEQUAL;
            *write_len = used_len + 1;
            break;

        case 'l':
            if (used_len + 4 > script_len || used_len + 4 > DESCRIPTOR_WITNESS_SCRIPT_MAX_SIZE)
                return WALLY_EINVAL;

            memmove(script + 3, script, used_len);
            script[0] = OP_IF;
            script[1] = OP_0;
            script[2] = OP_ELSE;
            script[used_len + 3] = OP_ENDIF;
            *write_len = used_len + 4;
            break;

        case 'u':
            if (used_len + 4 > script_len || used_len + 4 > DESCRIPTOR_WITNESS_SCRIPT_MAX_SIZE)
                return WALLY_EINVAL;

            memmove(script + 1, script, used_len);
            script[0] = OP_IF;
            script[used_len + 1] = OP_ELSE;
            script[used_len + 2] = OP_0;
            script[used_len + 3] = OP_ENDIF;
            *write_len = used_len + 4;
            break;

        default:
            return WALLY_EINVAL;     /* Wrapper type not found */
            break;
        }
    }
    return WALLY_OK;
}

static const struct miniscript_item_t miniscript_info_table[] = {
    /* output descriptor */
    {
        "sh", DESCRIPTOR_KIND_DESCRIPTOR_SH, 0, 1, verify_descriptor_sh, generate_by_descriptor_sh
    },
    {
        "wsh", DESCRIPTOR_KIND_DESCRIPTOR_WSH, 0, 1, verify_descriptor_wsh, generate_by_descriptor_wsh
    },
    {   /* c:pk_k */
        "pk", DESCRIPTOR_KIND_DESCRIPTOR_PK | DESCRIPTOR_KIND_MINISCRIPT_PK,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_X,
        1, verify_descriptor_pk, generate_by_descriptor_pk
    },
    {   /* c:pk_h */
        "pkh", DESCRIPTOR_KIND_DESCRIPTOR_PKH | DESCRIPTOR_KIND_MINISCRIPT_PKH,
        TYPE_B | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_X,
        1, verify_descriptor_pkh, generate_by_descriptor_pkh
    },
    {
        "wpkh", DESCRIPTOR_KIND_DESCRIPTOR_WPKH, 0, 1, verify_descriptor_wpkh, generate_by_descriptor_wpkh
    },
    {
        "combo", DESCRIPTOR_KIND_DESCRIPTOR_COMBO, 0, 1, verify_descriptor_combo, generate_by_descriptor_combo
    },
    {
        "multi", DESCRIPTOR_KIND_DESCRIPTOR_MULTI | DESCRIPTOR_KIND_MINISCRIPT_MULTI,
        TYPE_B | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S,
        1, verify_descriptor_multi, generate_by_descriptor_multi
    },
    {
        "sortedmulti", DESCRIPTOR_KIND_DESCRIPTOR_MULTI_S, 0, -1, verify_descriptor_sortedmulti, generate_by_descriptor_sorted_multi
    },
    {
        "addr", DESCRIPTOR_KIND_DESCRIPTOR_ADDR, 0, 1, verify_descriptor_addr, generate_by_descriptor_addr
    },
    {
        "raw", DESCRIPTOR_KIND_DESCRIPTOR_RAW, 0, 1, verify_descriptor_raw, generate_by_descriptor_raw
    },
    /* miniscript */
    {
        "pk_k", DESCRIPTOR_KIND_MINISCRIPT_PK_K,
        TYPE_K | PROP_O | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_X,
        1, verify_miniscript_pk, generate_by_miniscript_pk_k
    },
    {
        "pk_h", DESCRIPTOR_KIND_MINISCRIPT_PK_H,
        TYPE_K | PROP_N | PROP_D | PROP_U | PROP_E | PROP_M | PROP_S | PROP_X,
        1, verify_miniscript_pkh, generate_by_miniscript_pk_h
    },
    {
        "older", DESCRIPTOR_KIND_MINISCRIPT_OLDER,
        TYPE_B | PROP_Z | PROP_F | PROP_M | PROP_X,
        1, verify_miniscript_older, generate_by_miniscript_older
    },
    {
        "after", DESCRIPTOR_KIND_MINISCRIPT_AFTER,
        TYPE_B | PROP_Z | PROP_F | PROP_M | PROP_X,
        1, verify_miniscript_after, generate_by_miniscript_after
    },
    {
        "sha256", DESCRIPTOR_KIND_MINISCRIPT_SHA256,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_M,
        1, verify_miniscript_sha256, generate_by_miniscript_sha256
    },
    {
        "hash256", DESCRIPTOR_KIND_MINISCRIPT_HASH256,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_M,
        1, verify_miniscript_hash256, generate_by_miniscript_hash256
    },
    {
        "ripemd160", DESCRIPTOR_KIND_MINISCRIPT_RIPEMD160,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_M,
        1, verify_miniscript_ripemd160, generate_by_miniscript_ripemd160
    },
    {
        "hash160", DESCRIPTOR_KIND_MINISCRIPT_HASH160,
        TYPE_B | PROP_O | PROP_N | PROP_D | PROP_U | PROP_M,
        1, verify_miniscript_hash160, generate_by_miniscript_hash160
    },
    {
        "andor", DESCRIPTOR_KIND_MINISCRIPT_ANDOR, 0, 3, verify_miniscript_andor, generate_by_miniscript_andor
    },
    {
        "and_v", DESCRIPTOR_KIND_MINISCRIPT_AND_V, 0, 2, verify_miniscript_and_v, generate_by_miniscript_and_v
    },
    {
        "and_b", DESCRIPTOR_KIND_MINISCRIPT_AND_B, TYPE_B | PROP_U,
        2, verify_miniscript_and_b, generate_by_miniscript_and_b
    },
    {
        "and_n", DESCRIPTOR_KIND_MINISCRIPT_AND_N, 0, 2, verify_miniscript_and_n, generate_by_miniscript_and_n
    },
    {
        "or_b", DESCRIPTOR_KIND_MINISCRIPT_OR_B,
        TYPE_B | PROP_D | PROP_U,
        2, verify_miniscript_or_b, generate_by_miniscript_or_b
    },
    {
        "or_c", DESCRIPTOR_KIND_MINISCRIPT_OR_C, TYPE_V, 2, verify_miniscript_or_c, generate_by_miniscript_or_c
    },
    {
        "or_d", DESCRIPTOR_KIND_MINISCRIPT_OR_D, TYPE_B, 2, verify_miniscript_or_d, generate_by_miniscript_or_d
    },
    {
        "or_i", DESCRIPTOR_KIND_MINISCRIPT_OR_I, 0, 2, verify_miniscript_or_i, generate_by_miniscript_or_i
    },
    {
        "thresh", DESCRIPTOR_KIND_MINISCRIPT_THRESH,
        TYPE_B | PROP_D | PROP_U,
        -1, verify_miniscript_thresh, generate_by_miniscript_thresh
    }
};

static const struct miniscript_item_t *search_miniscript_info(const char *name, int target)
{
    const struct miniscript_item_t *result = NULL;
    size_t index;
    size_t max = sizeof(miniscript_info_table) / sizeof(struct miniscript_item_t);
    size_t name_len = strlen(name) + 1;

    for (index = 0; index < max; ++index) {
        if ((miniscript_info_table[index].kind & target) == 0)
            continue;
        if (memcmp(name, miniscript_info_table[index].name, name_len) == 0) {
            result = &miniscript_info_table[index];
            break;
        }
    }
    return result;
}

static int convert_bip32_path_to_array(
    const char *path,
    uint32_t *bip32_array,
    uint32_t array_num,
    bool is_private,
    uint32_t *count,
    int8_t *wildcard_pos_out)
{
    int ret = WALLY_OK;
    char *buf;
    char *temp;
    char *addr;
    size_t len;
    size_t index;
    bool hardened;
    uint32_t *array;
    int32_t value;
    char *err_ptr = NULL;
    int8_t wildcard_pos = -1;

    buf = wally_strdup(path);
    if (!buf)
        return WALLY_ENOMEM;

    if (!(array = wally_malloc(DESCRIPTOR_BIP32_PATH_NUM_MAX * sizeof(*array)))) {
        wally_free_string(buf);
        return WALLY_ENOMEM;
    }

    addr = buf;
    if (buf[0] == '/')
        addr += 1;

    for (index = 0; index < array_num + 1; ++index) {
        if (*addr == '\0')
            break;

        if (index == array_num) {
            ret = WALLY_EINVAL;
            break;
        }

        temp = strchr(addr, '/');
        if (temp) {
            *temp = '\0';
        }
        len = strlen(addr);
        if (!len) {
            ret = WALLY_EINVAL;
            break;
        }
        hardened = false;
        if (addr[len - 1] == '\'' || addr[len - 1] == 'h' || addr[len - 1] == 'H') {
            if (!is_private) {
                ret = WALLY_EINVAL;
                break;
            }
            addr[len - 1] = '\0';
            hardened = true;
            --len;
        }

        if (*addr == '\0') {
            ret = WALLY_EINVAL;
            break;
        }
        if (wildcard_pos != -1) {
            ret = WALLY_EINVAL;
            break;
        } else if (len == 1 && addr[len - 1] == '*') {
            wildcard_pos = (int8_t)index;
            array[index] = 0;
        } else {
            value = strtol(addr, &err_ptr, 10);
            if ((err_ptr && *err_ptr != '\0') || value < 0) {
                ret = WALLY_EINVAL;
                break;
            }
            array[index] = (uint32_t)value;
        }

        if (hardened) {
            array[index] |= 0x80000000;
        }

        if (temp) {
            addr = temp + 1;
        } else {
            ++index;
            break;
        }
    }

    if (ret == WALLY_OK && bip32_array) {
        memcpy(bip32_array, array, sizeof(uint32_t) * index);
        if (wildcard_pos_out)
            *wildcard_pos_out = wildcard_pos;
        if (count)
            *count = (uint32_t)index;
    }

    wally_free(array);
    wally_free_string(buf);
    return ret;
}

static int generate_script_from_number(
    int64_t number,
    struct miniscript_node_t *parent,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret = WALLY_OK;
    if (parent && !parent->info)
        return WALLY_EINVAL;

    if (script_len < DESCRIPTOR_NUMBER_BYTE_MAX_LENGTH)
        return WALLY_EINVAL;

    if (number == 0) {
        script[0] = 0;
        *write_len = 1;
    } else if (number == -1) {
        script[0] = OP_1NEGATE;
        *write_len = 1;
    } else if (number > 0 && number <= 16) {
        script[0] = OP_1 + number - 1;
        *write_len = 1;
    } else {
        unsigned char number_bytes[DESCRIPTOR_NUMBER_BYTE_MAX_LENGTH];
        size_t output_len = scriptint_to_bytes(number, number_bytes);
        if (!output_len)
            return WALLY_EINVAL;

        ret = wally_script_push_from_bytes(number_bytes, output_len, 0,
                                           script, script_len, write_len);
    }
    return ret;
}

static int generate_script_from_miniscript(
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent,
    uint32_t child_num,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    size_t output_len = 0;

    if (node->info) {
        output_len = *write_len;
        ret = node->info->generate_function(node, parent, child_num, script,
                                            script_len, &output_len);
        if (ret == WALLY_OK) {
            ret = generate_miniscript_wrappers(node, script, script_len, &output_len);
            if (ret == WALLY_OK)
                *write_len = output_len;
        }
        return ret;
    }

    /* value data */
    if (node->kind & DESCRIPTOR_KIND_RAW || node->kind == DESCRIPTOR_KIND_PUBLIC_KEY) {
        ret = wally_hex_to_bytes(node->data, script, script_len, write_len);
        if (ret == WALLY_OK && node->kind == DESCRIPTOR_KIND_PUBLIC_KEY) {
            if (*write_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
                node->is_uncompress_key = true;
            else if (*write_len == XONLY_PUBLIC_KEY_LEN)
                node->is_xonly_key = true;
        }
    } else if (node->kind == DESCRIPTOR_KIND_NUMBER) {
        ret = generate_script_from_number(node->number, parent, script, script_len, write_len);
    } else if (node->kind == DESCRIPTOR_KIND_BASE58 || node->kind == DESCRIPTOR_KIND_BECH32) {
        ret = analyze_miniscript_addr(node->data, NULL, NULL, NULL, script, script_len, write_len);
    } else if (node->kind == DESCRIPTOR_KIND_PRIVATE_KEY) {
        unsigned char privkey[2 + EC_PRIVATE_KEY_LEN + BASE58_CHECKSUM_LEN];
        unsigned char pubkey[EC_PUBLIC_KEY_LEN];
        if (script_len < EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
            return WALLY_EINVAL;

        ret = wally_base58_to_bytes(node->data, BASE58_FLAG_CHECKSUM, privkey,
                                    sizeof(privkey), &output_len);
        if (ret == WALLY_OK && output_len < EC_PRIVATE_KEY_LEN + 1)
            return WALLY_EINVAL;

        ret = wally_ec_public_key_from_private_key(&privkey[1], EC_PRIVATE_KEY_LEN,
                                                   pubkey, sizeof(pubkey));
        if (ret == WALLY_OK) {
            if (privkey[0] == WALLY_ADDRESS_VERSION_WIF_MAINNET) {
                if (node->network_type != 0 && node->network_type != WALLY_NETWORK_BITCOIN_MAINNET)
                    return WALLY_EINVAL;
                node->network_type = WALLY_NETWORK_BITCOIN_MAINNET;
            } else {
                if (node->network_type != 0 && node->network_type != WALLY_NETWORK_BITCOIN_TESTNET)
                    return WALLY_EINVAL;
                node->network_type = WALLY_NETWORK_BITCOIN_TESTNET;
            }
        }
        if (ret == WALLY_OK) {
            if (output_len == EC_PRIVATE_KEY_LEN + 2 && privkey[EC_PRIVATE_KEY_LEN + 1] == 1) {
                if (node->is_xonly_key) {
                    memcpy(script, &pubkey[1], XONLY_PUBLIC_KEY_LEN);
                    *write_len = XONLY_PUBLIC_KEY_LEN;
                } else {
                    memcpy(script, pubkey, EC_PUBLIC_KEY_LEN);
                    *write_len = EC_PUBLIC_KEY_LEN;
                }
            } else {
                ret = wally_ec_public_key_decompress(pubkey, sizeof(pubkey), script,
                                                     EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
                if (ret == WALLY_OK) {
                    *write_len = EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
                    node->is_uncompress_key = true;
                }
            }
        }
    } else if ((node->kind & DESCRIPTOR_KIND_BIP32) == DESCRIPTOR_KIND_BIP32) {
        unsigned char bip32_serialized[BIP32_SERIALIZED_LEN + BASE58_CHECKSUM_LEN];
        struct ext_key extkey;
        struct ext_key derive_extkey;
        uint32_t bip32_array[DESCRIPTOR_BIP32_PATH_NUM_MAX];
        int8_t wildcard_pos = -1;
        uint32_t count = 0;

        ret = wally_base58_to_bytes(node->data, BASE58_FLAG_CHECKSUM,
                                    bip32_serialized, sizeof(bip32_serialized), &output_len);
        if (ret != WALLY_OK)
            return ret;
        if (output_len > sizeof(bip32_serialized))
            return WALLY_EINVAL;

        ret = bip32_key_unserialize(bip32_serialized, output_len, &extkey);
        if (ret != WALLY_OK)
            return ret;

        if ((node->kind == DESCRIPTOR_KIND_BIP32_PRIVATE_KEY && extkey.version == BIP32_VER_MAIN_PRIVATE) ||
            (node->kind != DESCRIPTOR_KIND_BIP32_PRIVATE_KEY && extkey.version == BIP32_VER_MAIN_PUBLIC)) {
            if (node->network_type != 0 && node->network_type != WALLY_NETWORK_BITCOIN_MAINNET) {
                return WALLY_EINVAL;
            }
            node->network_type = WALLY_NETWORK_BITCOIN_MAINNET;
        } else {
            if (node->network_type != 0 && node->network_type != WALLY_NETWORK_BITCOIN_TESTNET) {
                return WALLY_EINVAL;
            }
            node->network_type = WALLY_NETWORK_BITCOIN_TESTNET;
        }

        if (node->derive_path && node->derive_path[0] != '\0') {
            ret = convert_bip32_path_to_array(node->derive_path, bip32_array,
                                              DESCRIPTOR_BIP32_PATH_NUM_MAX,
                                              (node->kind == DESCRIPTOR_KIND_BIP32_PRIVATE_KEY),
                                              &count, &wildcard_pos);
            if (ret != WALLY_OK)
                return ret;

            if (wildcard_pos >= 0)
                bip32_array[wildcard_pos] |= child_num;

            ret = bip32_key_from_parent_path(&extkey, bip32_array, count,
                                             BIP32_FLAG_KEY_PUBLIC, &derive_extkey);
            if (ret != WALLY_OK)
                return ret;

            memcpy(&extkey, &derive_extkey, sizeof(extkey));
        }
        if (node->is_xonly_key) {
            memcpy(script, &extkey.pub_key[1], XONLY_PUBLIC_KEY_LEN);
            *write_len = XONLY_PUBLIC_KEY_LEN;
        } else {
            memcpy(script, extkey.pub_key, EC_PUBLIC_KEY_LEN);
            *write_len = EC_PUBLIC_KEY_LEN;
        }
    } else {
        return WALLY_EINVAL;
    }

    return ret;
}

/*
 * Checksum code adapted from bitcoin core: bitcoin/src/script/descriptor.cpp DescriptorChecksum()
 */
/* The character set for the checksum itself (same as bech32). */
static const char *checksum_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const unsigned char checksum_positions[] = {
    0x5f, 0x3c, 0x5d, 0x5c, 0x1d, 0x1e, 0x33, 0x10, 0x0b, 0x0c, 0x12, 0x34, 0x0f, 0x35, 0x36, 0x11,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x1c, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x1b, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x0d, 0x5e, 0x0e, 0x3d, 0x3e,
    0x5b, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x1f, 0x3f, 0x20, 0x40
};

static inline size_t checksum_get_position(char c)
{
    return c < ' ' || c > '~' ? 0 : checksum_positions[(unsigned char)(c - ' ')];
}

static uint64_t poly_mod_descriptor_checksum(uint64_t c, int val)
{
    uint8_t c0 = c >> 35;
    c = ((c & 0x7ffffffff) << 5) ^ val;
    if (c0 & 1) c ^= 0xf5dee51989;
    if (c0 & 2) c ^= 0xa9fdca3312;
    if (c0 & 4) c ^= 0x1bab10e32d;
    if (c0 & 8) c ^= 0x3706b1677a;
    if (c0 & 16) c ^= 0x644d626ffd;
    return c;
}

static int generate_checksum(const char *src, size_t src_len, char *checksum_out)
{
    uint64_t c = 1;
    int cls = 0;
    int clscount = 0;
    size_t pos;
    size_t i;

    if (src_len > DESCRIPTOR_CHECKSUM_LENGTH && src[src_len - DESCRIPTOR_CHECKSUM_LENGTH - 1] == '#') {
        /* Ignore any existing checksum when calculating the checksum */
        src_len = src_len - DESCRIPTOR_CHECKSUM_LENGTH - 1;
    }

    for (i = 0; i < src_len; ++i) {
        if ((pos = checksum_get_position(src[i])) == 0)
            return WALLY_EINVAL; /* Invalid character */
        --pos;
        /* Emit a symbol for the position inside the group, for every character. */
        c = poly_mod_descriptor_checksum(c, pos & 31);
        /* Accumulate the group numbers */
        cls = cls * 3 + (int)(pos >> 5);
        if (++clscount == 3) {
            /* Emit an extra symbol representing the group numbers, for every 3 characters. */
            c = poly_mod_descriptor_checksum(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if (clscount > 0)
        c = poly_mod_descriptor_checksum(c, cls);
    for (i = 0; i < DESCRIPTOR_CHECKSUM_LENGTH; ++i)
        c = poly_mod_descriptor_checksum(c, 0);
    c ^= 1;

    for (i = 0; i < DESCRIPTOR_CHECKSUM_LENGTH; ++i)
        checksum_out[i] = checksum_charset[(c >> (5 * (7 - i))) & 31];
    checksum_out[DESCRIPTOR_CHECKSUM_LENGTH] = '\0';

    return WALLY_OK;
}

static int analyze_miniscript_addr(
    const char *message,
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent_node,
    const struct address_script_t *target_addr_item,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    char addr_family[90];
    unsigned char buf[SHA256_LEN + 2];
    unsigned char decoded[1 + HASH160_LEN + BASE58_CHECKSUM_LEN];
    size_t written;
    size_t i;

    if (parent_node && !node)
        return WALLY_EINVAL;

    if (script && (script_len < sizeof(buf) || !write_len))
        return WALLY_EINVAL;

    if (node) {
        node->data = wally_strdup(message);
        if (!node->data)
            return WALLY_ENOMEM;

        node->data_size = (uint32_t)strlen(message);
    }

    ret = wally_base58_to_bytes(message, BASE58_FLAG_CHECKSUM, decoded,
                                sizeof(decoded), &written);
    if (ret == WALLY_OK) {
        /* base58 address: Check for P2PKH/P2SH */
        const struct address_script_t *addr_item;
        bool is_p2sh;

        if (written != HASH160_LEN + 1)
            return WALLY_EINVAL; /* Unexpected address length */

        addr_item = netaddr_from_addr_version(decoded[0], target_addr_item, &is_p2sh);
        if (!addr_item)
            return WALLY_EINVAL; /* Network not found */

        if (node)
            node->kind = DESCRIPTOR_KIND_BASE58;

        if (script) {
            /* Create the scriptpubkey */
            ret = (is_p2sh ? wally_scriptpubkey_p2sh_from_bytes : wally_scriptpubkey_p2pkh_from_bytes)(
                decoded + 1, HASH160_LEN, 0, script, script_len, write_len);
        }
        return ret;
    }

    /* segwit */
    for (i = 0; i < sizeof(addr_family); ++i) {
        if (!message[i] || message[i] == '1') {
            addr_family[i] = '\0';
            break; /* Found (or end of string, wally_addr_segwit_to_bytes will fail below) */
        }
        addr_family[i] = message[i];
    }

    if (i == sizeof(addr_family))
        return WALLY_EINVAL; /* Address family too long for bech32 */

    if (target_addr_item && !netaddr_from_addr_family(addr_family, target_addr_item->network))
        return WALLY_EINVAL; /* Unknown network or address family mismatch */

    ret = wally_addr_segwit_to_bytes(message, addr_family, 0, buf, sizeof(buf), &written);
    if (ret == WALLY_OK && written != HASH160_LEN + 2 && written != SHA256_LEN + 2)
        ret = WALLY_EINVAL;

    if (ret == WALLY_OK) {
        if (node)
            node->kind = DESCRIPTOR_KIND_BECH32;
        if (script) {
            memcpy(script, buf, written);
            *write_len = written;
        }
    }
    return ret;
}

static int analyze_miniscript_key(
    const struct address_script_t *addr_item,
    uint32_t flags,
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent_node)
{
    int ret;
    size_t str_len = strlen(node->data);
    size_t buf_len;
    char *buf = NULL;
    int size;
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    unsigned char privkey_bytes[2 + EC_PRIVATE_KEY_LEN + BASE58_CHECKSUM_LEN];
    unsigned char bip32_serialized[BIP32_SERIALIZED_LEN + BASE58_CHECKSUM_LEN];
    struct ext_key extkey;

    if (!node || (parent_node && !parent_node->info))
        return WALLY_EINVAL;

    /*
     * key origin identification
     * https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#key-origin-identification
     */
    if (node->data[0] == '[') {
        buf = strchr(node->data, ']');
        if (!buf)
            return WALLY_EINVAL;

        size = (int)(buf - node->data + 1);
        if (!(node->key_origin_info = wally_malloc(size + 1)))
            return WALLY_ENOMEM;

        memcpy(node->key_origin_info, node->data, size);
        node->key_origin_info[size] = '\0';
        node->key_origin_info_len = size;
        /* cut parent path */
        memmove(node->data, buf + 1, str_len - size);
        str_len = str_len - size;
        node->data[str_len] = '\0';
    }

    /* check key (public key) */
    if ((flags & WALLY_MINISCRIPT_TAPSCRIPT) == 0 &&
        (str_len == EC_PUBLIC_KEY_LEN * 2 || str_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN * 2)) {
        ret = wally_hex_to_bytes(node->data, pubkey, sizeof(pubkey), &buf_len);
        if (ret == WALLY_OK) {
            node->kind = DESCRIPTOR_KIND_PUBLIC_KEY;
            if (str_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN * 2)
                node->is_uncompress_key = true;
            return wally_ec_public_key_verify(pubkey, buf_len);
        }
    }
    else if ((flags & WALLY_MINISCRIPT_TAPSCRIPT) != 0 && str_len == XONLY_PUBLIC_KEY_LEN * 2) {
        ret = wally_hex_to_bytes(node->data, pubkey, sizeof(pubkey), &buf_len);
        if (ret == WALLY_OK) {
            node->kind = DESCRIPTOR_KIND_PUBLIC_KEY;
            node->is_xonly_key = true;
            memmove(pubkey + 1, pubkey, buf_len);
            pubkey[0] = 2;
            return wally_ec_public_key_verify(pubkey, buf_len + 1);
        }
    }

    /* check key (private key(wif)) */
    ret = wally_base58_to_bytes(node->data, BASE58_FLAG_CHECKSUM, privkey_bytes,
                                sizeof(privkey_bytes), &buf_len);
    if (ret == WALLY_OK && buf_len <= EC_PRIVATE_KEY_LEN + 2) {
        if (addr_item && (addr_item->version_wif != privkey_bytes[0]))
            return WALLY_EINVAL;

        if (buf_len == EC_PRIVATE_KEY_LEN + 1 ||
            (buf_len == EC_PRIVATE_KEY_LEN + 2 && privkey_bytes[EC_PRIVATE_KEY_LEN + 1] == 0x01)) {
            node->kind = DESCRIPTOR_KIND_PRIVATE_KEY;
            if (buf_len == EC_PRIVATE_KEY_LEN + 1) {
                node->is_uncompress_key = true;
                if ((flags & WALLY_MINISCRIPT_TAPSCRIPT) != 0)
                    return WALLY_EINVAL;
            }
            if ((flags & WALLY_MINISCRIPT_TAPSCRIPT) != 0)
                node->is_xonly_key = true;
            return wally_ec_private_key_verify(&privkey_bytes[1], EC_PRIVATE_KEY_LEN);
        }
        return WALLY_EINVAL;
    }

    /* check bip32 key */
    buf = strchr(node->data, '/');
    if (buf) {
        if (buf[1] == '/')
            return WALLY_EINVAL;

        node->derive_path = wally_strdup(buf);
        if (!node->derive_path)
            return WALLY_ENOMEM;

        node->derive_path_len = (uint32_t)strlen(node->derive_path);
        *buf = '\0';
        str_len = strlen(node->data);
        if (strchr(node->derive_path, '*'))
            node->is_derive = true;
    }

    ret = wally_base58_to_bytes(node->data,
                                BASE58_FLAG_CHECKSUM,
                                bip32_serialized,
                                sizeof(bip32_serialized),
                                &buf_len);
    if (ret != WALLY_OK)
        return ret;
    if (buf_len > sizeof(bip32_serialized))
        return WALLY_EINVAL;

    ret = bip32_key_unserialize(bip32_serialized, buf_len, &extkey);
    if (ret != WALLY_OK)
        return ret;

    if (extkey.priv_key[0] == BIP32_FLAG_KEY_PRIVATE) {
        node->kind = DESCRIPTOR_KIND_BIP32_PRIVATE_KEY;
        if (extkey.version == BIP32_VER_MAIN_PRIVATE) {
            if (addr_item && (addr_item->network != WALLY_NETWORK_BITCOIN_MAINNET) &&
                (addr_item->network != WALLY_NETWORK_LIQUID))
                return WALLY_EINVAL;
        } else {
            if (addr_item && (addr_item->network == WALLY_NETWORK_BITCOIN_MAINNET ||
                              addr_item->network == WALLY_NETWORK_LIQUID))
                return WALLY_EINVAL;
        }
    } else {
        node->kind = DESCRIPTOR_KIND_BIP32_PUBLIC_KEY;
        if (extkey.version == BIP32_VER_MAIN_PUBLIC) {
            if (addr_item && (addr_item->network != WALLY_NETWORK_BITCOIN_MAINNET) &&
                (addr_item->network != WALLY_NETWORK_LIQUID))
                return WALLY_EINVAL;
        } else {
            if (addr_item && (addr_item->network == WALLY_NETWORK_BITCOIN_MAINNET ||
                              addr_item->network == WALLY_NETWORK_LIQUID))
                return WALLY_EINVAL;
        }
    }

    if ((flags & WALLY_MINISCRIPT_TAPSCRIPT) != 0)
        node->is_xonly_key = true;
    if (node->derive_path && node->derive_path[0] != '\0')
        ret = convert_bip32_path_to_array(node->derive_path,
                                          NULL,
                                          DESCRIPTOR_BIP32_PATH_NUM_MAX,
                                          (extkey.priv_key[0] == BIP32_FLAG_KEY_PRIVATE),
                                          NULL,
                                          NULL);
    return ret;
}

static int analyze_miniscript_value(
    const char *message,
    const struct wally_map *vars_in,
    uint32_t *network,
    uint32_t flags,
    struct miniscript_node_t *node,
    struct miniscript_node_t *parent_node)
{
    int ret;
    size_t message_len;
    size_t buf_len;
    char *buf = NULL;
    char *err_ptr = NULL;
    const struct address_script_t *addr_item = NULL;

    if (!node || (parent_node && !parent_node->info) || !message || !message[0])
        return WALLY_EINVAL;

    if (network && !(addr_item = netaddr_from_network(*network)))
        return WALLY_EINVAL; /* Unknown network */

    if (parent_node && (parent_node->info->kind == DESCRIPTOR_KIND_DESCRIPTOR_ADDR))
        return analyze_miniscript_addr(message, node, parent_node, addr_item, NULL, 0, NULL);

    message_len = strlen(message);

    if (vars_in) {
        /* Lookup map provided, map the message if found */
        size_t found_idx;
        ret = wally_map_find(vars_in, (const unsigned char *)message, message_len + 1, &found_idx);
        if (ret == WALLY_OK && found_idx) {
            node->data = wally_strdup((const char *)vars_in->items[found_idx - 1].value);
            if (!node->data)
                ret = WALLY_ENOMEM;
            else {
                message_len = vars_in->items[found_idx - 1].value_len - 1;
                node->data_size = message_len;
            }
        }
        if (ret != WALLY_OK)
            return ret;
    }

    if (!node->data) {
        node->data = wally_strdup(message);
        node->data_size = message_len;
    }

    if (parent_node &&
        (parent_node->info->kind == DESCRIPTOR_KIND_DESCRIPTOR_RAW ||
         parent_node->info->kind == DESCRIPTOR_KIND_MINISCRIPT_SHA256 ||
         parent_node->info->kind == DESCRIPTOR_KIND_MINISCRIPT_HASH256 ||
         parent_node->info->kind == DESCRIPTOR_KIND_MINISCRIPT_RIPEMD160 ||
         parent_node->info->kind == DESCRIPTOR_KIND_MINISCRIPT_HASH160)) {
        buf = wally_strdup(node->data);
        if (!buf)
            return WALLY_ENOMEM;

        ret = wally_hex_to_bytes(node->data, (unsigned char *)buf, message_len, &buf_len);
        if (ret == WALLY_OK) {
            node->kind = DESCRIPTOR_KIND_RAW;
        }
        wally_free_string(buf);
        return ret;
    }

    node->number = strtoll(node->data, &err_ptr, 10);
    if (!err_ptr || !*err_ptr) {
        node->kind = DESCRIPTOR_KIND_NUMBER;
        node->type_properties = TYPE_B | PROP_Z | PROP_U | PROP_M | PROP_X;
        if (node->number == 0) {
            node->type_properties |= PROP_D | PROP_E | PROP_S;
        } else {
            node->type_properties |= PROP_F;
        }
        return WALLY_OK;
    }

    return analyze_miniscript_key(addr_item, flags, node, parent_node);
}

static int analyze_miniscript(
    const char *miniscript,
    const struct wally_map *vars_in,
    uint32_t target,
    uint32_t *network,
    uint32_t flags,
    struct miniscript_node_t *prev_node,
    struct miniscript_node_t *parent_node,
    struct miniscript_node_t **generate_node,
    char *checksum_out)
{
    int ret = WALLY_OK;
    char *sub_str = NULL;
    size_t index;
    size_t str_len;
    size_t sub_str_len = 0;
    size_t offset = 0;
    size_t child_offset = 0;
    uint32_t indent = 0;
    bool collect_child = false;
    bool exist_indent = false;
    bool copy_child = false;
    char buffer[64];
    char checksum[DESCRIPTOR_CHECKSUM_LENGTH + 1];
    size_t checksum_index = 0;
    struct miniscript_node_t *node;
    struct miniscript_node_t *child = NULL;
    struct miniscript_node_t *prev_child = NULL;

    str_len = strlen(miniscript);

    if (!(node = wally_calloc(sizeof(*node))))
        return WALLY_ENOMEM;

    wally_bzero(buffer, sizeof(buffer));
    if (parent_node)
        node->parent = parent_node;

    for (index = 0; index < str_len; ++index) {
        if (!node->info && (miniscript[index] == ':')) {
            if (index - offset > sizeof(node->wrapper_str)) {
                ret = WALLY_EINVAL;
                break;
            }
            memcpy(node->wrapper_str, &miniscript[offset], index - offset);
            offset = index + 1;
        } else if (miniscript[index] == '(') {
            if (!node->info && (indent == 0)) {
                collect_child = true;
                memcpy(buffer, &miniscript[offset], index - offset);
                node->info = search_miniscript_info(buffer, target);
                if (!node->info) {
                    ret = WALLY_EINVAL;
                    break;
                } else if (node->wrapper_str[0] != '\0' &&
                           (node->info->kind & DESCRIPTOR_KIND_MINISCRIPT) == 0) {
                    ret = WALLY_EINVAL;
                    break;
                }
                offset = index + 1;
                child_offset = offset;
            }
            ++indent;
            exist_indent = true;
        } else if (miniscript[index] == ')') {
            if (indent) {
                --indent;
                if (collect_child && (indent == 0)) {
                    collect_child = false;
                    offset = index + 1;
                    copy_child = true;
                }
            }
            exist_indent = true;
        } else if (miniscript[index] == ',') {
            if (collect_child && (indent == 1)) {
                copy_child = true;
            }
            exist_indent = true;
        } else if (miniscript[index] == '#') {
            if (!parent_node && node->info && !collect_child && (indent == 0)) {
                checksum_index = index;
                if (strlen(&miniscript[index + 1]) > DESCRIPTOR_CHECKSUM_LENGTH)
                    ret = WALLY_EINVAL;
                break;  /* end */
            }
        }

        if (copy_child) {
            ret = realloc_substr_buffer(index - child_offset, &sub_str, &sub_str_len);
            if (ret != WALLY_OK)
                break;

            memcpy(sub_str, &miniscript[child_offset], index - child_offset);
            sub_str[index - child_offset] = '\0';
            ret = analyze_miniscript(sub_str,
                                     vars_in,
                                     target,
                                     network,
                                     flags,
                                     prev_child,
                                     node,
                                     &child,
                                     NULL);
            if (ret != WALLY_OK)
                break;

            prev_child = child;
            child = NULL;
            copy_child = false;
            if (miniscript[index] == ',') {
                offset = index + 1;
                child_offset = offset;
            }
        }
    }

    if (ret == WALLY_OK && !exist_indent)
        ret = analyze_miniscript_value(miniscript,
                                       vars_in,
                                       network,
                                       flags,
                                       node,
                                       parent_node);

    if (ret == WALLY_OK && node->info && node->info->verify_function)
        ret = node->info->verify_function(node, parent_node);

    if (ret == WALLY_OK && !parent_node && (checksum_index || checksum_out)) {
        /* Checksum is present or has been requested, generate it */
        char *checksum_p = checksum_out ? checksum_out : checksum;
        size_t expr_len = checksum_index ? checksum_index : str_len;
        ret = generate_checksum(miniscript, expr_len, checksum_p);
        if (ret == WALLY_OK && checksum_index &&
            strcmp(checksum_p, miniscript + checksum_index + 1) != 0) {
            /* Computed checksum does not match the one in the expression */
            ret = WALLY_EINVAL;
        }
    }

    if (ret == WALLY_OK)
        ret = verify_miniscript_wrappers(node);

    if (ret != WALLY_OK)
        free_miniscript_node(node);
    else {
        *generate_node = node;
        if (parent_node && !parent_node->child)
            parent_node->child = node;
        if (prev_node) {
            node->chain_count = prev_node->chain_count + 1;
            node->back = prev_node;
            prev_node->next = node;
        } else {
            node->chain_count = 1;
        }
    }

    clear_and_free(sub_str, sub_str_len);
    return ret;
}

static int convert_script_from_node(
    struct miniscript_node_t *top_node,
    uint32_t child_num,
    uint32_t depth,
    uint32_t index,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    char *buf;
    size_t output_len = 0;
    struct miniscript_node_t *target_node = top_node;
    uint32_t count;

    for (count = 0; count < depth; ++count) {
        if (!target_node->child)
            return WALLY_EINVAL;
        target_node = target_node->child;
    }
    for (count = 0; count < index; ++count) {
        if (!target_node->next)
            return WALLY_EINVAL;
        target_node = target_node->next;
    }

    if (!(buf = wally_malloc(DESCRIPTOR_LIMIT_LENGTH)))
        return WALLY_ENOMEM;

    ret = generate_script_from_miniscript(target_node,
                                          NULL,
                                          child_num,
                                          (unsigned char *)buf,
                                          DESCRIPTOR_LIMIT_LENGTH,
                                          &output_len);
    if (ret == WALLY_OK) {
        *write_len = output_len;
        if (output_len > script_len) {
            /* return WALLY_OK, but data is not written. */
        } else {
            memcpy(script, buf, output_len);
        }
    } else {
        *write_len = 0;
    }

    clear_and_free(buf, DESCRIPTOR_LIMIT_LENGTH);
    return ret;
}

static int parse_miniscript(
    const char *miniscript,
    const struct wally_map *vars_in,
    uint32_t flags,
    uint32_t target,
    uint32_t *network,
    uint32_t descriptor_depth,
    uint32_t descriptor_index,
    struct wally_descriptor_script_item *script_item,
    size_t item_len,
    uint32_t *properties,
    char *checksum_out)
{
    int ret;
    size_t i;
    unsigned char *work_script = NULL;
    size_t work_script_len = 0;
    unsigned char *temp_script = NULL;
    size_t temp_script_len = 0;
    size_t write_len;
    struct miniscript_node_t *top_node = NULL;

    if (((flags & ~0x1) != 0) || !miniscript ||
        !is_ascii_string(miniscript, DESCRIPTOR_LIMIT_LENGTH))
        return WALLY_EINVAL;

    if (vars_in) {
        for (i = 0; i < vars_in->num_items; ++i) {
            if (!is_ascii_string((char *)vars_in->items[i].key, DESCRIPTOR_KEY_NAME_MAX_LENGTH) ||
                !is_ascii_string((char *)vars_in->items[i].value, DESCRIPTOR_KEY_VALUE_MAX_LENGTH)) {
                return WALLY_EINVAL;
            }
        }
    }

    ret = analyze_miniscript(miniscript, vars_in, target, network, flags,
                             NULL, NULL, &top_node, checksum_out);
    if (ret == WALLY_OK && (target & DESCRIPTOR_KIND_DESCRIPTOR) &&
        (!top_node->info || !(top_node->info->kind & DESCRIPTOR_KIND_DESCRIPTOR)))
        ret = WALLY_EINVAL;
    if (ret == WALLY_OK && script_item) {
        for (i = 0; i < item_len; ++i) {
            write_len = 0;

            temp_script = script_item[i].script;
            temp_script_len = script_item[i].script_len;
            if (!temp_script) {
                if (!work_script) {
                    if (!(work_script = wally_malloc(DESCRIPTOR_LIMIT_LENGTH))) {
                        ret = WALLY_ENOMEM;
                        break;
                    }
                    work_script_len = DESCRIPTOR_LIMIT_LENGTH;
                }
                temp_script = work_script;
                temp_script_len = work_script_len;
            }
            ret = convert_script_from_node(top_node, script_item[i].child_num,
                                           descriptor_depth, descriptor_index,
                                           temp_script, temp_script_len,
                                           &write_len);
            if (ret != WALLY_OK)
                break;
            if (!script_item[i].script) {
                if (!(script_item[i].script = wally_malloc(write_len))) {
                    ret = WALLY_ENOMEM;
                    break;
                }
                memcpy(script_item[i].script, temp_script, write_len);
            }
            script_item[i].script_len = write_len;
        }
    }
    if (ret == WALLY_OK && properties)
        *properties = top_node->type_properties;

    clear_and_free(work_script, work_script_len);
    free_miniscript_node(top_node);
    return ret;
}

static int descriptor_scriptpubkey_to_address(
    const struct address_script_t *address_item,
    unsigned char *script,
    size_t script_len,
    char **output)
{
    int ret;
    int script_type = 0;
    size_t hash_len = 0;
    unsigned char hash[SHA256_LEN + 1];

    if (script_len == WALLY_SCRIPTPUBKEY_P2PKH_LEN &&
        script[0] == OP_DUP &&
        script[1] == OP_HASH160 &&
        script[2] == HASH160_LEN &&
        script[WALLY_SCRIPTPUBKEY_P2PKH_LEN - 2] == OP_EQUALVERIFY &&
        script[WALLY_SCRIPTPUBKEY_P2PKH_LEN - 1] == OP_CHECKSIG) {
        script_type = WALLY_SCRIPT_TYPE_P2PKH;
        hash[0] = address_item->version_p2pkh;
        memcpy(&hash[1], &script[3], HASH160_LEN);
        hash_len = HASH160_LEN + 1;
    } else if (script_len == WALLY_SCRIPTPUBKEY_P2SH_LEN &&
               script[0] == OP_HASH160 &&
               script[1] == HASH160_LEN &&
               script[WALLY_SCRIPTPUBKEY_P2SH_LEN - 1] == OP_EQUAL) {
        script_type = WALLY_SCRIPT_TYPE_P2SH;
        hash[0] = address_item->version_p2sh;
        memcpy(&hash[1], &script[2], HASH160_LEN);
        hash_len = HASH160_LEN + 1;
    } else if (script_len == WALLY_SCRIPTPUBKEY_P2WPKH_LEN &&
               script[0] == OP_0 && script[1] == HASH160_LEN) {
        script_type = WALLY_SCRIPT_TYPE_P2WPKH;
    } else if (script_len == WALLY_SCRIPTPUBKEY_P2WSH_LEN &&
               script[0] == OP_0 &&
               script[1] == SHA256_LEN) {
        script_type = WALLY_SCRIPT_TYPE_P2WSH;
        /* feature: append witness v1 */
    } else {
        ret = WALLY_EINVAL;
    }

    if (script_type == WALLY_SCRIPT_TYPE_P2PKH || script_type == WALLY_SCRIPT_TYPE_P2SH) {
        ret = wally_base58_from_bytes(hash, hash_len, BASE58_FLAG_CHECKSUM, output);
    } else if (script_type == WALLY_SCRIPT_TYPE_P2WPKH ||
               script_type == WALLY_SCRIPT_TYPE_P2WSH) {
        const uint32_t flags = 0;
        ret = wally_addr_segwit_from_bytes(script, script_len, address_item->addr_family, flags, output);
    }
    return ret;
}

int wally_descriptor_parse_miniscript(
    const char *miniscript,
    const struct wally_map *vars_in,
    uint32_t child_num,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written)
{
    int ret;
    struct wally_descriptor_script_item script_item = { bytes_out, len, child_num };

    if (written)
        *written = 0;

    if (!bytes_out || !written || !len)
        return WALLY_EINVAL;

    ret = parse_miniscript(
        miniscript,
        vars_in,
        flags,
        DESCRIPTOR_KIND_MINISCRIPT,
        NULL,
        0,
        0,
        &script_item,
        1,
        NULL,
        NULL);
    if (ret == WALLY_OK)
        *written = script_item.script_len;
    return ret;
}

int wally_descriptor_to_scriptpubkey(
    const char *descriptor,
    const struct wally_map *vars_in,
    uint32_t child_num,
    uint32_t network,
    uint32_t target_depth,
    uint32_t target_index,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written)
{
    int ret;
    const struct address_script_t *addr_item;
    struct wally_descriptor_script_item script_item = { bytes_out, len, child_num };

    if (written)
        *written = 0;

    if (!bytes_out || !written || !len)
        return WALLY_EINVAL;

    addr_item = netaddr_from_network(network);

    ret = parse_miniscript(
        descriptor,
        vars_in,
        flags,
        DESCRIPTOR_KIND_MINISCRIPT | DESCRIPTOR_KIND_DESCRIPTOR,
        addr_item ? &network : NULL,
        target_depth,
        target_index,
        &script_item,
        1,
        NULL,
        NULL);
    if (ret == WALLY_OK)
        *written = script_item.script_len;
    return ret;
}

int wally_descriptor_to_addresses(const char *descriptor, const struct wally_map *vars_in,
                                  uint32_t child_num, uint32_t network, uint32_t flags,
                                  char **addresses, size_t num_addresses)
{
    const struct address_script_t *addr_item = netaddr_from_network(network);
    struct wally_descriptor_script_item *scripts;
    size_t i;
    int ret;

    if (addresses && num_addresses)
        wally_bzero(addresses, num_addresses * sizeof(*addresses));

    if (!descriptor || !addr_item || !addresses || !num_addresses)
        return WALLY_EINVAL;

    if (!(scripts = wally_calloc(num_addresses * sizeof(*scripts))))
        return WALLY_ENOMEM;

    for (i = 0; i < num_addresses; ++i)
        scripts[i].child_num = child_num + i;

    ret = parse_miniscript(descriptor, vars_in, flags,
                           DESCRIPTOR_KIND_MINISCRIPT | DESCRIPTOR_KIND_DESCRIPTOR,
                           &network, 0, 0, scripts, num_addresses, NULL, NULL);

    for (i = 0; i < num_addresses && ret == WALLY_OK; ++i)
        ret = descriptor_scriptpubkey_to_address(addr_item,
                                                 scripts[i].script, scripts[i].script_len,
                                                 &addresses[i]);

    for (i = 0; i < num_addresses; ++i) {
        clear_and_free(scripts[i].script, scripts[i].script_len);
        if (ret != WALLY_OK) {
            wally_free_string(addresses[i]);
            addresses[i] = NULL;
        }
    }
    clear_and_free(scripts, num_addresses * sizeof(*scripts));
    return ret;
}

int wally_descriptor_to_address(const char *descriptor, const struct wally_map *vars_in,
                                uint32_t child_num, uint32_t network, uint32_t flags,
                                char **output)
{
    return wally_descriptor_to_addresses(descriptor, vars_in, child_num, network, flags, output, 1);
}

int wally_descriptor_create_checksum(const char *descriptor,
                                     const struct wally_map *vars_in, uint32_t flags,
                                     char **output)
{
    char checksum[DESCRIPTOR_CHECKSUM_LENGTH + 1];
    int ret;

    if (output)
        *output = NULL;

    if (!descriptor || !output || flags)
        return WALLY_EINVAL;

    ret = parse_miniscript(descriptor, vars_in, flags,
                           DESCRIPTOR_KIND_MINISCRIPT | DESCRIPTOR_KIND_DESCRIPTOR,
                           NULL, 0, 0, NULL, 0, NULL, checksum);

    if (ret == WALLY_OK && !(*output = wally_strdup(checksum)))
        ret = WALLY_ENOMEM;
    return ret;
}
