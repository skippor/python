#include <Python.h>
#include "calc.h"

static PyObject* example_add(PyObject* self, PyObject* args)
{
    int a,b;
    if (!PyArg_ParseTuple(args, "ii", &a, &b)) {
        return NULL;
    }
    return Py_BuildValue("i", myadd(a,b));
}

static PyObject* example_sub(PyObject* self, PyObject* args)
{
    int a,b;
    if (!PyArg_ParseTuple(args, "ii", &a, &b)) {
        return NULL;
    }
    return Py_BuildValue("i", mysub(a,b));
}

static PyObject* example_mul(PyObject* self, PyObject* args)
{
    int a,b;
    if (!PyArg_ParseTuple(args, "ii", &a, &b)) {
        return NULL;
    }
    return Py_BuildValue("i", mymul(a,b));
}

static PyObject* example_div(PyObject* self, PyObject* args)
{
    float a,b;
    if (!PyArg_ParseTuple(args, "ff", &a, &b)) {
        return NULL;
    }
    return Py_BuildValue("f", mydiv(a,b));
}

static PyMethodDef example_methods[] =
{
    {"add", (PyCFunction)example_add, METH_VARARGS, "add(a,b): return a+b"},
    {"sub", (PyCFunction)example_sub, METH_VARARGS, "sub(a,b): return a-b"},
    {"mul", (PyCFunction)example_mul, METH_VARARGS, "mul(a,b): return a*b"},
    {"div", (PyCFunction)example_div, METH_VARARGS, "div(a,b): return a/b"},
    {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef samplemodule = {
  PyModuleDef_HEAD_INIT,
  "example",           /* name of module */
  "A sample module",  /* Doc string (may be NULL) */
  -1,                 /* Size of per-interpreter state or -1 */
  example_methods       /* Method table */
};

PyMODINIT_FUNC PyInit_example(void) {
  return PyModule_Create(&samplemodule);
}

#else
PyMODINIT_FUNC initexample(void)
{
    Py_InitModule3("example", example_methods, "Extension module example!");
}
#endif
