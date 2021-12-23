sources = [
  'otr_key.c',
  'otr_ops.c',
  'otr_util.c',
  'hexchat_otr.c',
]

sources += custom_target('formats',
  input: 'formats.txt',
  output: ['hexchat-formats.c', 'otr-formats.h'],
  command: [find_program('makeformats.py'), '@INPUT@', '@OUTDIR@']
)

shared_module('otr', sources,
  dependencies: [
    glib_dep,
    otr_dep,
    # gcrypt_dep,
    hexchat_dep,
    config_dep,
  ],
  link_args: gcrypt_libs,
  c_args: gcrypt_cflags,
  name_prefix: '',
  install: true,
  install_dir: hexchatplugindir,
)
