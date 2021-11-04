#ifndef LIBWALLY_CORE_DESCRIPTOR_H
#define LIBWALLY_CORE_DESCRIPTOR_H

#include "wally_core.h"
#include "wally_address.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wally_map;

#define WALLY_NETWORK_BITCOIN_REGTEST 0xff  /** Bitcoin regtest */

/* Miniscript type flag */
#define WALLY_MINISCRIPT_WITNESS_SCRIPT  0x00
#define WALLY_MINISCRIPT_TAPSCRIPT       0x01

/**
 * Create a script corresponding to a miniscript string.
 *
 * :param miniscript: Miniscript string.
 * :param vars_in: Map of variable names to values.
 * :param child_num: The BIP32 child number to derive.
 * :param flags: For analyze type.
 *|   see WALLY_MINISCRIPT_WITNESS_SCRIPT, WALLY_MINISCRIPT_TAPSCRIPT.
 * :param bytes_out: Destination for the resulting scriptPubkey.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_descriptor_parse_miniscript(
    const char *miniscript,
    const struct wally_map *vars_in,
    uint32_t child_num,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Create a scriptPubKey corresponding to a output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param vars_in: Map of variable names to values.
 * :param child_num: The BIP32 child number to derive.
 * :param network: Number of the network. (bitcoin regtest is set ``0xff``)
 * :param target_depth: Number of the descriptor depth. Default is 0.
 * :param target_index: Number of the descriptor index. Default is 0.
 * :param flags: For future use. Must be 0.
 * :param bytes_out: Destination for the resulting scriptPubkey.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_descriptor_to_scriptpubkey(
    const char *descriptor,
    const struct wally_map *vars_in,
    uint32_t child_num,
    uint32_t network,
    uint32_t target_depth,
    uint32_t target_index,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Create an address corresponding to a output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param vars_in: Map of variable names to values.
 * :param child_num: The BIP32 child number to derive.
 * :param network: Number of the network. (bitcoin regtest is set ``0xff``)
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting addresss.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_to_address(
    const char *descriptor,
    const struct wally_map *vars_in,
    uint32_t child_num,
    uint32_t network,
    uint32_t flags,
    char **output);

/**
 * Create addresses that correspond to the derived range of an output descriptor.
 *
 * :param descriptor: Output descriptor.
 * :param vars_in: Map of variable names to values.
 * :param child_num: The first BIP32 child number to derive.
 * :param network: Number of the network. (bitcoin regtest is set ``0xff``)
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting addresses.
 * :param num_outputs: The number of items in ``output``. Addresses will be
 *|    generated into this array starting from child_num, incrementing by 1.
 *|    The addresses returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_to_addresses(
    const char *descriptor,
    const struct wally_map *vars_in,
    uint32_t child_num,
    uint32_t network,
    uint32_t flags,
    char **output,
    size_t num_outputs);

/**
 * Create an output descriptor checksum.
 *
 * :param descriptor: Output descriptor.
 * :param vars_in: Map of variable names to values.
 * :param flags: For future use. Must be 0.
 * :param output: Destination for the resulting descriptor checksum.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_descriptor_create_checksum(
    const char *descriptor,
    const struct wally_map *vars_in,
    uint32_t flags,
    char **output);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_DESCRIPTOR_H */
