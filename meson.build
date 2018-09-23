project('hexchat-otr', 'c',
  version: '0.2.2',
  meson_version: '>= 0.46',
  default_options: [
    'c_std=gnu99',
    'buildtype=debugoptimized',
    'warning_level=2',
  ]
)

cc = meson.get_compiler('c')

add_project_arguments(cc.get_supported_arguments([
  '-fvisibility=hidden',
  '-funsigned-char',
  '-fstack-protector-strong',
  '-fPIE',
  '-fPIC',
  '-Wconversion',
  '-Winline',
  '-Wno-padded',
  '-Wno-unused-parameter',
  '-Wstrict-prototypes',
  '-Wmissing-prototypes',
  '-Werror=implicit-function-declaration',
  '-Werror=pointer-arith',
  '-Werror=init-self',
  '-Werror=format=2',
  '-Werror=missing-include-dirs',
  '-Werror=date-time',
]), language: 'c')

add_project_link_arguments(cc.get_supported_link_arguments([
  '-Wl,-z,relro',
  '-Wl,-z,now',
]), language: 'c')

config = configuration_data()
config.set_quoted('PACKAGE_VERSION', meson.project_version())
configure_file(
  configuration: config,
  output: 'config.h',
)
config_dep = declare_dependency(include_directories: include_directories('.'))

glib_dep = dependency('glib-2.0')
otr_dep = dependency('libotr', version: '>= 4.0.0')
hexchat_dep = dependency('hexchat-plugin')
# Added in 0.49
# https://github.com/mesonbuild/meson/pull/4246
# gcrypt_dep = dependency('libgcrypt')

gcrypt_config = find_program('libgcrypt-config')
ret = run_command([gcrypt_config, '--cflags'])
if ret.returncode() != 0
  error('Failed to get gcrypt flags')
endif
gcrypt_cflags = ret.stdout().strip().split()
ret = run_command([gcrypt_config, '--libs'])
if ret.returncode() != 0
  error('Failed to get gcrypt libs')
endif
gcrypt_libs = ret.stdout().strip().split()

if get_option('local_install')
  # Replace this with check: true in 0.47+
  ret = run_command([find_program('hexchat'), '--configdir'])
  if ret.returncode() != 0
    error('Failed to get hexchat configdir')
  endif
  hexchatplugindir = join_paths(ret.stdout().strip(), 'addons')
else
  hexchatplugindir = hexchat_dep.get_pkgconfig_variable('hexchatlibdir')
endif
message('Install location: ' + hexchatplugindir)

subdir('src')
