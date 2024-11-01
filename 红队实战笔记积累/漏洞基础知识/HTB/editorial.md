1 nmap扫描
2 dirb爆破路径后 无法先
3 /etc/hosts添加域环境 登录后burp尝试上传 抓包  结果 
![[Pasted image 20240616152131.png]]
会清除痕迹找不到哦啊
document.getElementById('button-cover').addEventListener('click', function(e) {
  e.preventDefault();

  // 获取表单数据
  var formData = new FormData(document.getElementById('form-cover'));

  // 创建一个新的 XMLHttpRequest 对象
  var xhr = new XMLHttpRequest();

  // 配置请求
  xhr.open('POST', '/upload-cover');

  // 设置响应处理函数
  xhr.onload = function() {
    if (xhr.status === 200) {
      var imgUrl = xhr.responseText;
      console.log(imgUrl);
      document.getElementById('bookcover').src = imgUrl;

      document.getElementById('bookfile').value = '';
      document.getElementById('bookurl').value = '';
    }
  };

  // 发送表单数据
  xhr.send(formData);
});
