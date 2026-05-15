private import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks
import MySummaries

module MyUnsafeDeserializationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    isGPTDetectedSource(src)
  }

  predicate isSink(DataFlow::Node sink) {
    isGPTDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    none()
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    isGPTDetectedStep(n1, n2)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module MyUnsafeDeserializationFlow =
  TaintTracking::Global<MyUnsafeDeserializationConfig>;
