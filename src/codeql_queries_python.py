PYTHON_QL_SOURCE_PREDICATE = """\
private import python
import semmle.python.dataflow.new.DataFlow
private import semmle.python.ApiGraphs

predicate isGPTDetectedSource(DataFlow::Node src) {{
{body}
}}

{additional}
"""

PYTHON_QL_SINK_PREDICATE = """\
private import python
import semmle.python.dataflow.new.DataFlow
private import semmle.python.ApiGraphs

private string irisExprName(Expr e) {{
  e instanceof Name and result = e.(Name).getId()
  or
  e instanceof Attribute and result = irisExprName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
  or
  not e instanceof Name and
  not e instanceof Attribute and
  result = e.toString()
}}

private string irisCallName(Call c) {{
  result = irisExprName(c.getFunc())
}}

predicate isGPTDetectedSink(DataFlow::Node snk) {{
{body}
}}

{additional}
"""

PYTHON_QL_STEP_PREDICATE = """\
private import python
import semmle.python.dataflow.new.DataFlow
private import semmle.python.ApiGraphs

private string irisExprName(Expr e) {{
  e instanceof Name and result = e.(Name).getId()
  or
  e instanceof Attribute and result = irisExprName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
  or
  not e instanceof Name and
  not e instanceof Attribute and
  result = e.toString()
}}

private string irisCallName(Call c) {{
  result = irisExprName(c.getFunc())
}}

predicate isGPTDetectedStep(DataFlow::Node prev, DataFlow::Node next) {{
{body}
}}
"""

PYTHON_QL_API_SOURCE_ENTRY = """\
    {api_expr}.getACall().getReturn().asSource() = src\
"""

PYTHON_QL_FUNC_PARAM_SOURCE_ENTRY = """\
    exists(Function f, Parameter p |
        f.getQualifiedName() = "{function}" and
        (
            f.getArgByName("{param}") = p
            or
            ({param_index} >= 0 and f.getArg({param_index}) = p)
        ) and
        p.asName().getAFlowNode() = src.asCfgNode()
    )\
"""

PYTHON_QL_API_SINK_ARG_ENTRY = """\
    (
        {api_expr}.getACall().getParameter({arg_id}, "").asSink() = snk
        or
        exists(Call call |
            irisCallName(call) = "{call_name}" and
            call.getArg({arg_id}) = snk.asExpr()
        )
    )\
"""

PYTHON_QL_STEP_ENTRY = """\
    (
        exists(API::CallNode call |
            call = {api_expr}.getACall() and
            prev = call.getParameter({arg_id}, "").asSink() and
            next = call.getReturn().asSource()
        )
        or
        exists(Call call |
            irisCallName(call) = "{call_name}" and
            call.getArg({arg_id}) = prev.asExpr() and
            DataFlow::exprNode(call) = next
        )
    )\
"""
