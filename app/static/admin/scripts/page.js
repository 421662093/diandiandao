//分页按钮生成 http地址前缀  total总页数 index当前页码
function Pagebtn(http,total,index) {  
var preNum=index;if(index>1)preNum-=1;else preNum=1;
var NextNum=index;if(index<total)NextNum+=1;else NextNum=total;
if(total>1)
{
    var Pre='<li class="prev'+(index==1?' disabled':'')+'"><a href="'+http+'/'+preNum+'" title="Prev"><i class="fa fa-angle-left"></i></a></li>';
    var Next='<li class="next'+(index==total?' disabled':'')+'"><a href="'+http+'/'+NextNum+'" title="Next"><i class="fa fa-angle-right"></i></a></li>';

    var str=Pre;
    if(total<=5)
    {
      for(var i=1;i<=total;i++)str=str+"<li"+(index==i?' class="active"':'')+"><a href='"+http+'/'+i+"'>"+i+"</a></li>";
    }
    else
    {
      if(index>=5)
      {
          var temp=total-index;str=str+"<li"+(index==1?' class="active"':'')+"><a href='"+http+"/1'>1</a></li>";str=str+'<li class="disabled"><a href="#">...</a></li>';
          if(temp>=4)
          {
              for(var i=index-2;i<=index+2;i++)str=str+"<li"+(index==i?' class="active"':'')+"><a href='"+http+'/'+i+"'>"+i+"</a></li>";
              str=str+'<li class="disabled"><a href="#">...</a></li>';str=str+"<li"+(index==total?' class="active"':'')+"><a href='"+http+'/'+total+"'>"+total+"</a></li>";
          }
          else
          {
              for(var i=index-(4-temp);i<=total;i++)str=str+"<li"+(index==i?' class="active"':'')+"><a href='"+http+'/'+i+"'>"+i+"</a></li>";
          }
      }
      else
      {
        for(var i=1;i<=5;i++)str=str+"<li"+(index==i?' class="active"':'')+"><a href='"+http+'/'+i+"'>"+i+"</a></li>";
        str=str+'<li class="disabled"><a href="#">...</a></li>';str=str+"<li"+(index==total?' class="active"':'')+"><a href='"+http+'/'+total+"'>"+total+"</a></li>";
      }
    }
    str=str+Next;
	document.write(str);
}
}