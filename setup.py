from distutils.core import setup, Extension

c_ext = Extension("hckeyspace", ["hckeyspace.c"])

setup(
    ext_modules=[c_ext]
)
