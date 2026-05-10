CPP_QL_SOURCE_PREDICATE = """\
private import cpp
import semmle.code.cpp.ir.dataflow.DataFlow

predicate isGPTDetectedSource(DataFlow::Node src) {{
{body}
}}

{additional}
"""

CPP_QL_SINK_PREDICATE = """\
private import cpp
import semmle.code.cpp.ir.dataflow.DataFlow

predicate isGPTDetectedSink(DataFlow::Node snk) {{
{body}
}}

{additional}
"""

CPP_QL_STEP_PREDICATE = """\
private import cpp
import semmle.code.cpp.ir.dataflow.DataFlow

predicate isGPTDetectedStep(DataFlow::Node prev, DataFlow::Node next) {{
{body}
}}
"""

CPP_QL_API_SOURCE_ENTRY = """\
    exists(FunctionCall call |
        call.getTarget().getName() = "{function}" and
        DataFlow::exprNode(call) = src
    )\
"""

CPP_QL_FUNC_PARAM_SOURCE_ENTRY = """\
    exists(Function f, Parameter p |
        f.getName() = "{function}" and
        (
            p.getName() = "{param}"
            or
            ({param_index} >= 0 and f.getParameter({param_index}) = p)
        ) and
        (
            DataFlow::parameterNode(p) = src
            or
            p = src.asParameter()
        )
    )\
"""

CPP_QL_API_SINK_ARG_ENTRY = """\
    exists(FunctionCall call |
        call.getTarget().getName() = "{function}" and
        (
            call.getArgument({arg_id}) = snk.asExpr()
            or
            call.getArgument({arg_id}) = snk.asIndirectArgument()
        )
    )\
"""

CPP_QL_STEP_ARG_TO_RETURN_ENTRY = """\
    exists(FunctionCall call |
        call.getTarget().getName() = "{function}" and
        (
            DataFlow::exprNode(call.getArgument({arg_id})) = prev
            or
            call.getArgument({arg_id}) = prev.asIndirectArgument()
        ) and
        DataFlow::exprNode(call) = next
    )\
"""

CPP_QL_STEP_ARG_TO_OUTPUT_ARG_ENTRY = """\
    exists(FunctionCall call |
        call.getTarget().getName() = "{function}" and
        (
            DataFlow::exprNode(call.getArgument({src_arg_id})) = prev
            or
            call.getArgument({src_arg_id}) = prev.asIndirectArgument()
        ) and
        (
            call.getArgument({dst_arg_id}) = next.asDefiningArgument()
            or
            DataFlow::exprNode(call.getArgument({dst_arg_id})) = next
        )
    )\
"""
