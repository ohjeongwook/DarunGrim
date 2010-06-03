import DarunGrimDatabaseWrapper

class PatternAnalyzer:
	SecurityImpactPatterns = ( 
			( "match", "cmp", 1 ),
			( "match", "test", 1 ),
			( "match", "wcslen", 2 ),
			( "match", "strlen", 2 ),
			( "match", "0xFFFFFFF", 3 ),
			( "match", "StringCchCopyW", 2 )
	)
	
	def __init__( self ):
		pass

	def GetDisasmLinesWithSecurityImplications( self, lines  ):
		return_lines = ''

		security_implications_score = 0
		for line in lines:
			for ( type, pattern, weight ) in self.SecurityImpactPatterns:
				if type == 'match' and line.find( pattern ) >= 0:
					security_implications_score += weight
					line = '<div class="SecurityImplication">' + line + '</div>'
			return_lines += '<p>' + line

		return ( security_implications_score, return_lines )

	def GetSecurityImplicationsScore( self, databasename, source_address, target_address ):
		database = DarunGrimDatabaseWrapper.Database( databasename )
	
		source_address = int(source_address)
		target_address = int(target_address)

		comparison_table = database.GetDisasmComparisonTextByFunctionAddress( source_address, target_address )
		
		left_line_security_implications_score_total = 0
		right_line_security_implications_score_total = 0
		for ( left_address, left_lines, right_address, right_lines, match_rate ) in comparison_table:
			left_line_security_implications_score = 0
			right_line_security_implications_score = 0
			if (right_address == 0 and left_address !=0) or match_rate < 100 :
				( left_line_security_implications_score, left_line_text ) = self.GetDisasmLinesWithSecurityImplications( left_lines )

			if (left_address == 0 and right_address !=0) or match_rate < 100 :
				( right_line_security_implications_score, right_line_text ) = self.GetDisasmLinesWithSecurityImplications( right_lines )

			left_line_security_implications_score_total += left_line_security_implications_score
			right_line_security_implications_score_total += right_line_security_implications_score

		return right_line_security_implications_score_total
