add_atsplugin(avx_tee_decrypt tee_decrypt.cc tee_info.cc)

target_link_libraries(avx_tee_decrypt)
verify_global_plugin(avx_tee_decrypt)
