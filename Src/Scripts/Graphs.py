import sys
from PySide.QtGui import *
from PySide.QtCore import *
import FlowGrapher

TYPE_DI_RECTS=0
TYPE_DI_DRAW=1
TYPE_DI_GRAPH=2

TYPE_DI_COLOR=3
TYPE_DI_FILLCOLOR=4
TYPE_DI_BGCOLOR=5
TYPE_DI_FONTCOLOR=6

class FunctionGraphScene(QGraphicsScene):
	Debug=0
	def __init__(self,parent=None):
		QGraphicsScene.__init__(self,parent)

	def InvertedQPointF(self,x,y):
		return QPointF(x,self.GraphRect[3]-y)

	def Draw(self,flow_grapher):
		self.clear()
		self.setSceneRect(-180,-90,360,180)
		flow_grapher.GenerateDrawingInfo()
		len=flow_grapher.GetDrawingInfoLength()

		pen_color=''
		font_size=''
		font_name=''

		self.GraphRect=[0,0,0,0]

		for i in range(0,len,1):
			di=flow_grapher.GetDrawingInfoMember(i)

			if di.type==TYPE_DI_GRAPH:
				self.GraphRect=[di.GetPoint(0).x, di.GetPoint(0).y,di.GetPoint(1).x, di.GetPoint(1).y]
				self.setSceneRect(QRectF(di.GetPoint(0).x, di.GetPoint(0).y,di.GetPoint(1).x, di.GetPoint(1).y))

			if di.type==TYPE_DI_COLOR:
				pen_color=di.text

			if di.type==TYPE_DI_FILLCOLOR:
				fill_color=di.text

			if di.type==TYPE_DI_BGCOLOR:
				bg_color=di.text

			if di.type==TYPE_DI_FONTCOLOR:
				font_color=di.text

			if di.type==TYPE_DI_RECTS:
					polygon=QPolygonF()
					for j in range(0, di.count,1):
						polygon.append(self.InvertedQPointF(di.GetPoint(j).x, di.GetPoint(j).y))

					pen=QPen(QColor(pen_color))
					brush=QBrush(QColor(bg_color))
					#self.addPolygon(polygon, pen, brush)

			if di.type==TYPE_DI_DRAW:
				type_ch=chr(di.subtype)
				if type_ch=='L':
					start_x=di.GetPoint(0).x
					start_y=di.GetPoint(0).y

					end_x=di.GetPoint(1).x
					end_y=di.GetPoint(1).y

					if self.Debug>0:
						print 'Line %d,%d - %d,%d' % (di.GetPoint(0).x, di.GetPoint(0).y, di.GetPoint(1).x, di.GetPoint(1).y)
					
					line=QGraphicsLineItem(QLineF(self.InvertedQPointF(start_x,start_y),self.InvertedQPointF(end_x,end_y)))
					line.setPen(QPen(Qt.black))
					self.addItem(line)

				elif type_ch=='P' or type_ch=='p':
					polygon=QPolygonF()
					for j in range(0, di.count,1):
						polygon.append(self.InvertedQPointF(di.GetPoint(j).x, di.GetPoint(j).y))

					pen=None
					brush=None
					if pen_color:
						pen=QPen(self.GetColor(pen_color))

					if type_ch=='P' and fill_color!='':
						print type_ch, fill_color
						brush=QBrush(self.GetColor(fill_color))

					self.addPolygon(polygon, pen, brush)

				elif type_ch=='B' or type_ch=='b':
					print 'Bezier:'
					for j in range(0, di.count,1):
						print '\t%d,%d' % (di.GetPoint(j).x, di.GetPoint(j).y)

					for i in range(0,di.count-1,3):
						path=QPainterPath(self.InvertedQPointF(di.GetPoint(i).x, di.GetPoint(i).y))
					
						path.cubicTo(
										self.InvertedQPointF(di.GetPoint(i+1).x, di.GetPoint(i+1).y),
										self.InvertedQPointF(di.GetPoint(i+2).x, di.GetPoint(i+2).y),
										self.InvertedQPointF(di.GetPoint(i+3).x, di.GetPoint(i+3).y)
									)
						self.addPath(path);

				elif type_ch=='F':
					font_size=di.size
					font_name=di.text

				elif type_ch=='c':
					pen_color=di.text

				elif type_ch=='C':
					fill_color=di.text

				elif type_ch=='T':
					if self.Debug>0:
						print "%s %s %s %s" % (di.text, font_name, font_size, pen_color)

					text_item=QGraphicsTextItem()

					if pen_color:
						text_item.setDefaultTextColor(self.GetColor(pen_color))

					font=QFont(font_name)
					font.setPixelSize(font_size)
					text_item.setFont(font)
					text_item.setPlainText(di.text)
					w=text_item.boundingRect().width()
					text_item.setPos(di.GetPoint(0).x-w/2, (self.GraphRect[3] - di.GetPoint(0).y) - font_size - 3 )

					self.addItem(text_item)

	def GetColor(self, color_str):
		if color_str:
			if color_str[0]=='#':
				color_name=color_str[0:7]

				try:
					alpha=int(color_str[7:],16)
				except:
					pass
			else:
				color_name=color_str
				alpha=0xff

		color=QColor(color_name)
		color.setAlpha(alpha)
		return color

if __name__=='__main__':
	class MainWindow(QMainWindow):
		def __init__(self):
			QMainWindow.__init__(self)
			scene=FunctionGraphScene()
			self.scene=scene

			flow_grapher=FlowGrapher.FlowGrapher()
			flow_grapher.SetNodeShape("black", "white", "Verdana", "10")
			flow_grapher.AddNode(0, "Test 0", "Disasm lines")
			flow_grapher.AddNode(1, "Test 1", "Disasm lines")
			flow_grapher.AddNode(2, "Test 2", "Disasm lines")
			flow_grapher.AddNode(3, "Test 3", "Disasm lines")
			flow_grapher.AddLink(0,1)
			flow_grapher.AddLink(0,2)
			flow_grapher.AddLink(0,3)
			flow_grapher.AddLink(1,3)
			flow_grapher.AddLink(1,4)
			scene.Draw(flow_grapher)

			layout=QHBoxLayout()
			self.view=QGraphicsView(self.scene)
			self.view.setRenderHints(QPainter.Antialiasing)
			layout.addWidget(self.view)

			self.widget=QWidget()
			self.widget.setLayout(layout)

			self.setCentralWidget(self.widget)
			self.setWindowTitle("Graph")

	app=QApplication(sys.argv)
	frame=MainWindow()
	frame.setGeometry(100,100,800,500)
	frame.show()
	sys.exit(app.exec_())

