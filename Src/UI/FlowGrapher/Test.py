import FlowGrapher

flow_grapher=FlowGrapher.FlowGrapher()
flow_grapher.SetNodeShape("black", "red", "Arial", "12")
flow_grapher.AddNode(0, "Test 0", "Disasm lines")
flow_grapher.AddNode(1, "Test 1", "Disasm lines")
flow_grapher.AddLink(0,1)

flow_grapher.GenerateDrawingInfo()
len=flow_grapher.GetDrawingInfoLength()
for i in range(0,len,1):
	di=flow_grapher.GetDrawingInfoMember(i)
	print "address: %x type: %d subtype: %c size: %d text: %s" % (di.address, di.type, di.subtype, di.size, di.text)

	for j in range(0,di.count,1):
		print '\t %d,%d' % (di.GetPoint(j).x, di.GetPoint(j).y)
