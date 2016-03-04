# resourceful-acl
`resourceful-acl`是一个简单的基于角色访问控制列表的授权管理express 中间件.适用于RESTful的uri

##安装
```shell
npm install resourceful-acl
```

###使用

```javascript
var Acl = require('resourceful-acl');
var options = {
  //定义如何获取角色,默认从req.user.role中获取角色
  get_role:function(req,callback){     
    if(req.user && req.user.role){
      callback(null,req.user.role);
    }else{
      callback(null,false);
    }
  },
  //定义当无法获取当前访问用户的角色时启用的角色，默认为'default'
  default:'reader',
  //消息,调用acl.authorize()时会传递给回调函数
  success_message:'授权成功',
  failure_message:'请登录'
};

var accessList = {
   //定义一个默认角色,当无法获取当前访问用户的角色时启用
  'default':{
    'index':'view',        // 允许读 '/',view等价于['get','option','head']
    'posts':'view',        // 允许访问 posts资源 即允许访问下列url
                           //     '/posts'
                           //     '/posts/{param}'
                           //     '/posts/{param}/path'
    'posts_images':'view', // 允许访问 posts 的images嵌套资源,即
                           //     '/posts/{params}/images'
                           //     '/posts/{params}/images/{image-param}'
                           //     '/posts/{params}/images/{image-param}/path'
    'custom_resource':{    // 如果资源较为复杂，可以使用自定义资源
      path: /^\/custom_resource\/?(\d+?\/?)?$/,  //定义一个正则表达式用于匹配请求路径
      methods:['get','post']                     //定义允许的请求方法
    },
    'users':null           // 将请求方法设置为null，则可以禁止所有方法的访问
  },
  'editor':{               // 定义另一个角色
    extends:'default',     // 角色继承，即editor拥有与default一样的权限
    resources:{            // 定义资源
      'posts': 'edit',     // 在default的基础上扩展权限,edit 相当于['put','post','patch']
      'posts_images':['edit','delete'],
      'users':'*'          // '*' 即允许所有方法
    }
  }
}

acl = new Acl(options,accessList);

/*使用中间件*/
//方法零
//授权失败会抛出错误(err.code===403)，成功则调用next
app.use(acl.authorize());

//方法一
//如果授权失败，跳转到指定目录,成功或者资源为定义则调用next()

app.use(acl.authorize({
  //指定重定向的url
  failure_redirect:'/login',      

  //指定是否发送flash信息，值为true或者字符串,默认值为false.默认发送的flash是在options中定义的failure_message,这里可以指定一个字符串
  flash:true,                 
}));

//方法二,自定义
app.use(function(req,res,next){
  acl.authorize(function(err,info,status){
    if(err){
      req.flash('danger','请登录');
      return res.redirect('/login');
    }else{
      next();
    }
  })(req,res,next);
});

```

