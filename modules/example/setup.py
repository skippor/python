from setuptools import setup, Extension

setup(name="example", 
    ext_modules=[
      Extension("example",
                ["example.c", "calc.c"],
                include_dirs = ['.'],
                )
      ]
)


