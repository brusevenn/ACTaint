import os,sys,unittest
from pathlib import Path
from unittest.mock import patch
SRC=Path(__file__).resolve().parents[1]/"src"
sys.path.insert(0,str(SRC))
from llm.sink_agent import SinkAgent
from llm.taint_agent import TaintAgent
class StablePrefixTests(unittest.TestCase):
 def test_native_sink_fixed_rules_and_format_precede_variable_source(self):
  with patch.dict(os.environ,{"ACTAINT_PROMPT_LAYOUT":"prefix_stable_v2"}):
   a=SinkAgent("rules-A","ctor-A","SOURCE_A").generate_prompt()
   b=SinkAgent("rules-B","ctor-B","SOURCE_B").generate_prompt()
  self.assertEqual(len(a),2)
  x=a[1]["content"];y=b[1]["content"]
  self.assertEqual(x[:x.index("SOURCE_A")],y[:y.index("SOURCE_B")])
  self.assertLess(x.index("--Sink--:"),x.index("SOURCE_A"))
  for v in ("SOURCE_A","rules-A","ctor-A"):self.assertIn(v,x)
 def test_native_taint_format_and_rules_preserved(self):
  with patch.dict(os.environ,{"ACTAINT_PROMPT_LAYOUT":"prefix_stable_v2"}):
   x=TaintAgent("SINK_A","ctor-A","SOURCE_A").generate_prompt()[1]["content"]
  for v in ("SINK_A","ctor-A","SOURCE_A","--Vulnerability--:"):self.assertIn(v,x)
  self.assertLess(x.index("--Vulnerability--:"),x.index("SOURCE_A"))
class SourceDelimiterTests(unittest.TestCase):
 def test_embedded_delimiter_does_not_enter_fixed_prefix(self):
  source="contract A { /* "+chr(96)*3+". VARIABLE_SUFFIX */ }"
  with patch.dict(os.environ,{"ACTAINT_PROMPT_LAYOUT":"prefix_stable_v2"}):
   for agent in (SinkAgent("rule","ctor",source),TaintAgent("sink","ctor",source)):
    content=agent.generate_prompt()[1]["content"]
    self.assertEqual(content.count("VARIABLE_SUFFIX"),1)
    self.assertGreater(content.index("VARIABLE_SUFFIX"),content.index("Source code:"))
if __name__=="__main__":unittest.main()
