//网页信息提取

var tb = $('body > table:nth-child(8) > tbody > tr > td > table > tbody');    // table 的 id
var rows = tb.rows;                           // 获取表格所有行
var result = new Array();
for(var i = 0; i<rows.length; i++ ){
   for(var j = 0; j<rows[i].cells.length; j++ ){    // 遍历该行的 td
	result.push(rows[i].cells[0].innerText)	
   }
}
console.log(result.join('\n'))
