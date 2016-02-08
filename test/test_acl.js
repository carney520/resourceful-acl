var acl = require("../index");
var chai = require('chai');
var expect = chai.expect;

chai.use(require("./test_helper"));

//test method map
describe("test methodMap",function(){
  var input = [
    {i:"*",o:"*"},
    {i:"get",o:["get"]},
    {i:"view",o:["get","head","options"]},
    {i:"edit",o:["put","post","patch"]},
    {i:["get","post","head"],o:["get","post","head"]},
    {i:["view","delete"],o:["get","head","options","delete"]}
  ];
  it("should return o",function(){
    input.forEach(function(item){
      expect(acl.methodMap(item.i)).to.eql(item.o);
    });
  });
});

describe("test getResourcePath",function(){
  var pathVariable = '([^/]+?/?)?';
  var slash = "/?";
  var data = [
    {i:"index",o:{path:'^/$',belongs_to:null,priority:1}},
    {i:"posts",o:{path:'^/posts'+slash + pathVariable + pathVariable+'$',
                   belongs_to:null,priority:1
                 }},
    {i:"posts_attachments",o:{path:'^/posts'+slash + pathVariable + '/attachments'+slash + pathVariable + pathVariable + '$',
                               belongs_to:"posts",priority:2}}
  ];

  it("should return o",function(){
    data.forEach(function(item){
      expect(acl.getResourcePath(item.i)).to.eql(item.o);
    });
  });
});

describe("test permissionCompile",function(){
  it("the compile permission assignment should eql output",function(){
    var input = {
      reader:{
        index:"get",
        posts:"get",
        posts_attachments:"get"
      },
      editor:{
        extends:'reader',
        resources:{
          posts:['edit'],
          posts_attachments:['delete']
        }
      }
    };

    var pathOfPosts = acl.getResourcePath('posts'),
        pathOfPostsAttachments = acl.getResourcePath('posts_attachments'),
        pathOfIndex = acl.getResourcePath('index');

    var ouput ={
      reader:{
        parents:null,
        resources:[
          {"name":"index",
            "path":new RegExp(pathOfIndex.path,'i'),
            "methods":["get"],
            "belongs_to":pathOfIndex.belongs_to,
            "priority":pathOfIndex.priority
          },
          {
            "name":"posts",
            "path":new RegExp(pathOfPosts.path,'i'),
            "methods":["get"],
            "belongs_to":pathOfPosts.belongs_to,
            "priority":pathOfPosts.priority
          },
          {
            "name":"posts_attachments",
            "path":new RegExp(pathOfPostsAttachments.path,'i'),
            "methods":["get"],
            "belongs_to":pathOfPostsAttachments.belongs_to,
            "priority":pathOfPostsAttachments.priority
          }
        ]
      },
      editor:{
        parents:['reader'],
        resources:[
          {
            "name":'posts',
            "path":new RegExp(pathOfPosts.path,'i'),
            "methods":acl.methodMap("edit"),
            "belongs_to":pathOfPosts.belongs_to,
            "priority":pathOfPosts.priority
          },
          {
            "name":"posts_attachments",
            "path":new RegExp(pathOfPostsAttachments.path,'i'),
            "methods":acl.methodMap("delete"),
            "belongs_to":pathOfPostsAttachments.belongs_to,
            "priority":pathOfPostsAttachments.priority
          }
        ]
      }
    };
    expect(acl.permissionCompile(input)).to.eql(ouput);
    
  });
});

describe("test authorize",function(){
  before(function(){
    //compile permissions
    var role_assignment = {
      reader:{
        index:"get",
        posts:"get",
        posts_attachments:"get"
      },
      contributor:{
        manuscripts:'*',
        customize_resources:{
          path:/^\/customize\/?(\d+)?$/,
          methods:"get"
        }
      },
      editor:{
        extends:['reader','contributor'],
        resources:{
          posts:['edit'],
          posts_attachments:['delete']
        }
      }
    };

    //add compiled result to acl
    acl.__compiled = acl.permissionCompile(role_assignment);
    console.log(acl.__compiled.contributor.resources);
  });


  var edit = ["post","put","patch"];
  var index_path = "/",
      posts_path = ["/posts","/posts/:id","/posts/:id/mix"],
      posts_attachments_path = ["/posts/:id/attachments","/posts/:id/attachments/:id","/posts/:id/attachments/:id/method"],
      manuscripts_path = ["/manuscripts","/manuscripts/","/manuscripts/:id",
    "/manuscripts/:id/edit","/manuscripts/:id/edit/"],
      customize_resources_path = ["/customize","/customize/","/customize/89"];

  describe("test role for 'reader'",function(){
    var role = 'reader';

    describe("test noexistent resources",function(){
      var undefined_resources = ["/user","/about","/posts/:id/method/god",
        "posts/:id/attachments/:id/method/notfound",
        "/posts/:id/edit/attachments/:id"
      ];
      it("should non_match the resource,suggest return 404",function(){
        undefined_resources.forEach(function(path){
          expect(acl.check(role,path,'get')).to.be.non_match;
        });
      });
    });

    describe("test index",function(){
      var index_path = "/";

      it("should allowed when get index on '/'",function(){
        expect(acl.check(role,index_path,'get')).to.be.allowed;
      });

      it("should denied when post,put,patch,or delete the index on '/'",function(){
        var deny_methods = ['post','put','patch','delete'];
        deny_methods.forEach(function(method){
          expect(acl.check(role,index_path,method)).to.be.denied;
        });
      });
    });

    describe("test posts",function(){

      it("should allow to get /posts,/posts/:id or /posts/:id/method",function(){
        posts_path.forEach(function(path){
          expect(acl.check(role,path,'get')).to.be.allowed;
        });
      });

      it("should deny to edit or delete posts",function(){
        edit.concat('delete').forEach(function(method){
          posts_path.forEach(function(path){
            expect(acl.check(role,path,method)).to.be.denied;
          });
        });
      });
    });

    describe("test posts_attachments",function(){

      it("should allow to get posts_attachments",function(){
        posts_attachments_path.forEach(function(path){
          expect(acl.check(role,path,"get")).to.be.allowed;
        });
      });

      it("should deny to edit or delete posts_attachments",function(){
        posts_attachments_path.forEach(function(path){
          edit.concat('delete').forEach(function(method){
            expect(acl.check(role,path,method)).to.be.denied;
          });
        });
      });
    });
    //end of reader
  }); 

  describe("test role for contributor",function(){
    var role = "contributor";
    
    it("should allow contributor to get manuscripts",function(){
      manuscripts_path.forEach(function(path){
        expect(acl.check(role,path,"get")).to.be.allowed;
      });
    });

    it("should allow contributor to edit and delete manuscripts",function(){
      manuscripts_path.forEach(function(path){
        edit.concat('delete').forEach(function(method){
          expect(acl.check(role,path,method)).to.be.allowed;
        });
      });
    });

    describe("test customize resource",function(){
      it("should allow contributor to get customize_resources",function(){
        customize_resources_path.forEach(function(path){
          expect(acl.check(role,path,'get')).to.be.allowed;
        });
      });
    });
    //end of contributor
  });

  describe("test role for 'editor'",function(){
    var role = "editor";

    describe("test role inherit",function(){
      // editor inherit from reader
      it("should allow editor to get index,posts and posts_attachments",function(){
        //index
        expect(acl.check(role,index_path,'get')).to.be.allowed.as('reader');
        //posts
        posts_path.forEach(function(path){
          expect(acl.check(role,path,'get')).to.be.allowed.as('reader');
        });
        //posts_attachments
        posts_attachments_path.forEach(function(path){
          expect(acl.check(role,path,'get')).to.be.allowed.as('reader');
        });
        //manuscripts 
        manuscripts_path.forEach(function(path){
          expect(acl.check(role,path,'get')).to.be.allowed.as('contributor');
        });
      });

      it("should allow editor to edit and delete manuscripts_path",function(){
        manuscripts_path.forEach(function(path){
          edit.concat('delete').forEach(function(method){
            expect(acl.check(role,path,method)).to.be.allowed.as('contributor');
          });
        });
      });
    });

    describe("test editor permission",function(){
      it("should allow editor to edit posts",function(){
        posts_path.forEach(function(path){
          edit.forEach(function(method){
            expect(acl.check(role,path,method)).to.be.allowed.as(role);
          });
        });
      });

      it("should deny editor to delete posts",function(){
        posts_path.forEach(function(path){
          expect(acl.check(role,path,'delete')).to.be.denied.as(role);
        });
      });
    });

    describe("test nested resources",function(){

      it("should allow editor to delete posts_attachments",function(){
        posts_attachments_path.forEach(function(path){
          expect(acl.check(role,path,"delete")).to.be.allowed;
        });
      });
    });
    //end of editor
  });
});


describe("test express middleware",function(){
  //init access control list
  var middleware = null,
      res = {},
      next = function(err){
        if(err) throw err;
      },
      index_path = "/",
      posts_path = ["/posts","/posts/90","/posts/90/edit","/posts/90/edit/"],
      edit_methods = ["POST","PUT","PATCH"];

  var setupRequest = function(method,path,role){
    if(!method || !path){
      throw new Error("require request method and request path");
    }
    var req = {};
    req.method = method.toUpperCase(method);
    req.path = path;

    if(role){
      req.user = {role:role};
    }
    return req;
  };


  before(function(){
    acl({default:'reader'},{
      reader:{
        index:"view",
        posts:"view"
      },
      editor:{
        extends:"reader",
        resources:{
          posts:"edit"
        }
      }
    });
    middleware = acl.authorize();
  });

  describe("test visitors ,they will treat as 'reader'",function(){
    it("should treat visitors as 'reader'",function(done){
      var req = setupRequest('get','/');
      //Asynchronous test,it should excute without error
      middleware(req,res,done);
      expect(req.acl).to.be.allowed.as("reader");
    });

    posts_path.forEach(function(path){
      it("should allow visitors to GET "+path,function(done){
        var req=setupRequest('get',path);
        middleware(req,res,done);
        expect(req.acl).to.be.allowed.as("reader");
      });
    });
  });

  describe("test reader",function(){
    var role = 'reader';
    it("should allow reader to GET '/'",function(done){
      var req = setupRequest('get','/',role);
      middleware(req,res,done);
    });

    it("should deny reader to edit or delete the post",function(done){
      var req = setupRequest('post','/posts/90',role);
      var next = function(err){
        if(err){
          expect(err.code).to.equal(403);
          expect(err).to.be.denied;
          done();
        }
      };
      middleware(req,res,next);
    });
  });

  describe("test editor",function(){
    var role = "editor";
    it("should allow editor to GET index",function(done){
      var req = setupRequest('get','/',role);
      middleware(req,res,done);
    });

    it("should allow editor to edit /posts",function(){
      edit_methods.forEach(function(method){
        var req = setupRequest(method,'/posts/id',role);
        middleware(req,res,next);
        expect(req.acl).to.be.allowed.as('editor');
      });
    });
  });
});
