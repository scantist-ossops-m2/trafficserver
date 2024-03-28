add_atsplugin(avx_certifier avx_certifier.cc)

target_link_libraries(avx_certifier PRIVATE OpenSSL::Crypto OpenSSL::SSL)
verify_global_plugin(avx_certifier)
