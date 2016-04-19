
##eclipse Paho MQTT协议封装源码解析


//The core of the client, which holds the state information for pending and in-flight messages.

ClientState：protected void notifyReceivedMsg(MqttWireMessage message)


ClientComms整体负责与Mqtt服务器进行交互（交互的核心在于socket的链接），其抽象出两个任务，分别是ConnectBG和DisconnectBG。


ConnectBG用于在一个work线程中处理链接，便于不阻塞（因为socket链接需要花时间进行处理），其在线程中创建代表处理接受从服务器发送过来的消息的 CommsReceiver，以及 代表 向服务器发送消息的 CommsSender。


其中， CommsReceiver 被抽象成一个 接受 从服务器发送过来消息的 task，并在一个单独的线程 通过 socket.getInputStream() 来获取小心进行处理。


## MQTT协议封装源码解析

MQTT(MQ Telemetry Transport)是IBM开发的基于轻量级的、基于"发布/订阅"模式的消息传输协议,用于有限制的设备(比如嵌入式设备)和低带宽、高延迟或不可靠的网络。

MQTT官网：[http://mqtt.org/](http://mqtt.org/ "http://mqtt.org/")

优点：协议简洁、小巧、可扩展性强、省流量、省电，应用到企业领域，已有多个开源项目提供参考。

针对eclipse对Mqtt客户端封装(download uri: [org.eclipse.paho.android.service.sample](https://github.com/eclipse/paho.mqtt.java/tree/master/org.eclipse.paho.android.service/org.eclipse.paho.android.service.sample "eclipse paho"))做简要分析.


### 理解核心

* MQTT本质是通过建立与mosquitto 服务器 的Socket 链接来进行通信（这里介绍仅以TCP的为主，其client中还支持ssl）；
* 传送的数据包是通过MQTT协议来组织的；
* 多线程的同步

### 找到切入点

初步拿到改代码，会看到各种回调，各种消息的封装，难免会感到有些混乱， 那么如何跟踪整个代码的逻辑，上面说过，MQTT client本质是通过建立一个socket链接进行通信。所以我们全局搜索 Socket关键字，会发现：

	org.eclipse.paho.client.mqttv3.internal.NetworkModule
	org.eclipse.paho.client.mqttv3.internal.TCPNetworkModule

其提供socket链接操作的基本入口

	public interface NetworkModule {
		public void start() throws IOException, MqttException;
		
		public InputStream getInputStream() throws IOException;
		
		public OutputStream getOutputStream() throws IOException;
		
		public void stop() throws IOException;
	}
	

看到上面接口，我们可以猜想下：

* start中应该会做 socket.connect()操作，去连接 mosquitto（默认端口为1883） 服务器，并且此方法应该是在一个worker线程中去执行（避免阻塞ui线程）；
* 通过getInputStream()和getOutputStream()获取socket 输入输出，接受MqttMessage package进行处理；
* stop用于关闭socket连接；


抛出一个问题：

>如何封装一个socket请求，或者说 如何快速搭建一个socket链接请求框架？？

> 需要考虑：
> 
> * 接口的提取
> * 数据获取和发送如何组织
> * 如何将结果回调给客户端  

### 延伸

找到切入点之后，接下来的事情就好办了，主要就是看 callback 的传递以及各种异步同步的处理。

先给出eclipse paho mqtt android 客户端正对mqtt的封装大概思路

![eclipse mqtt](http://i.imgur.com/G4ymtT7.jpg)

简单解释下这个图：

MqttAndroidClient ： 代表最上层操作 mqtt 相关动作的接口（ 如，连接服务器（connect）、发布消息（publish）等）

MqttAsyncClient ： 代表服务端针对 mqtt 做的一个封装，其运行在一个Service中，并负责 与mosquitto 服务器简历socket链接，和向服务器推送消息以及从服务器中接受回传过来的消息（如publish、subscrib）;

MqttAsyncClient 将 与服务器 进行操作的动作的 结果，通过广播的形式 通知 MqttAndroidClient ，从而使 MqttAndroidClient得知当前 消息的处理状态；

消息从 MqttAndroidClient 到 MqttAsyncClient 的关联是通过 一个activityToken的标识来标识的；


简而言之，就是通过调用  MqttAndroidClient 的 connect 等操作，启动一个服务，建立 与 服务端 代表 MqttAsyncClient 的关联， 而服务端 代表 MqttAsyncClient 通过简历 与 server的 socket链接，并从server获得Mqtt消息包进行处理，并通过 广播 通知 MqttAndroidClient 处理结果，进而 MqttAndroidClient 将最终的结果加以客户单显示。

### flow code

现在 以 connect 为例，来跟踪下整个代码的流程；

在跟踪之前，先说明几个问题：

1.将整个 eclipse paho mqtt 客户端的代码我们暂且根绝整个流程分为 client端和service端；并且这里跳过client端ui的显示方面的过程，只跟踪到回调的arrived。

2.client端 包括 ui callback回调以及 动作的触发；

3.server端 包括 socket的建立，以及 发布消息和订阅消息等的处理，还有回调的组织等；

根据上面的分类，我们先来看 Client的代码流程。

#### Client

step1:触发connect动作，设置ActionListener以及addCallback

	private void connectAction(Bundle data) {
		// 链接请求的 一些options，例如username、password等
		MqttConnectOptions conOpt = new MqttConnectOptions();
		...

		String uri = null; //用于简历 tcp请求 uri
		if (ssl) {
			Log.e("SSLConnection", "Doing an SSL Connect");
			uri = "ssl://";

		} else {
			uri = "tcp://";
		}

		uri = uri + server + ":" + port;

		client = Connections.getInstance(this)
				.createClient(this, uri, clientId);

		if (ssl) { //如果是ssl链接，则需要创建sslSocketFactory等，这里仅分析tcl链接
			....
		}

		//用作当前Connection的key值，在客户端，将client封装一个Connection对象
		clientHandle = uri + clientId;

		// 获取用户的相关登录信息

		String username = (String) data.get(ActivityConstants.username);

		String password = (String) data.get(ActivityConstants.password);

		
		Connection connection = new Connection(clientHandle, clientId, server,
				port, this, client, ssl);

		
		// connect client

		connection.changeConnectionStatus(ConnectionStatus.CONNECTING);

		conOpt.setCleanSession(cleanSession);
		conOpt.setConnectionTimeout(timeout);
		conOpt.setKeepAliveInterval(keepalive);
		if (!username
				.equals(com.boyaa.customer.service.main.ActivityConstants.empty)) {
			conOpt.setUserName(username);
		}
		if (!password.equals(ActivityConstants.empty)) {
			conOpt.setPassword(password.toCharArray());
		}

		//动作处理 listener，如connect、disConnect等
		callback = new ActionListener(this, ActionListener.Action.CONNECT,
				clientHandle, actionArgs) {
			@Override
			public void connect() {
				super.connect();
				Log.d(TAG, "connect to broker successfully");
			}
		};

		boolean doConnect = true;

		
		client.setCallback(mqttCallbackHandler);// 消息接收和连接监视器

		// set traceCallback
		client.setTraceCallback(new MqttTraceCallback());

		connection.addConnectionOptions(conOpt);
		Connections.getInstance(this).addConnection(connection);
		if (doConnect) {
			try {
				Log.d(TAG, "connect to MQTT server");
				client.connect(conOpt, null, callback);
			} catch (MqttException e) {
				Log.e(this.getClass().getCanonicalName(),
						"MqttException Occured", e);
			}
		}

	}

这里有三个需要注意的：

1.MqttAndroidClient 的创建；

	client = Connections.getInstance(this).createClient(this, uri, clientId);

2.代表 MqttAndroidClient 的 Connection的存储；

	Connection connection = new Connection(clientHandle, clientId, server,port, this, client, ssl);
	Connections.getInstance(this).addConnection(connection);

3.消息接收和连接监视器的添加；

	client.setCallback(mqttCallbackHandler);// 消息接收和连接监视器

4.动作ActionListener的监听；

	client.connect(conOpt, null, callback);

**下来我们逐一分析下**

第1点和第2点配合起来看

//com.boyaa.customer.service.main.Connections

	public MqttAndroidClient createClient(Context context, String serverURI, String clientId)
	{
	    MqttAndroidClient client = new MqttAndroidClient(context, serverURI, clientId);
	    return client;
	}


	public void addConnection(Connection connection)
	  {
	    connections.put(connection.handle(), connection);
	    try {
	      persistence.persistConnection(connection);
	    }
	    catch (PersistenceException e)
	    {
	      //error persisting well lets just swallow this
	      e.printStackTrace();
	    }
	  }

点开源码，我们看到，第1点就是创建了一个 MqttAndroidClient 对象，并将其创建的实例 传入 Connection 的构造函数中,并且调用 addConnection ，以 connection.handle()（其为clientHandle， 即 uri + clientId）为key，所创建的connection为vaule，将其存入一个Map中。

备注：com.boyaa.customer.service.main.Connections 是一个单例类，并管理  Connection ，而Connection是持有MqttAndroidClient实例，因此，可以 通过 Connection 获得 MqttAndroidClient实例。

第3点添加了一个MqttCallback 对象，其用于处理

	public interface MqttCallback {
	
		//链接丢失
		public void connectionLost(Throwable cause);
		
		//服务器有消息推送
		public void messageArrived(String topic, MqttMessage message) throws Exception;
		
		//传递消息
		public void deliveryComplete(IMqttDeliveryToken token);
	}

第四点 调用 connect方法

	public IMqttToken connect(MqttConnectOptions options, Object userContext,
				IMqttActionListener callback) throws MqttException {
	
			IMqttToken token = new MqttTokenAndroid(this, userContext,
					callback);
	
			connectOptions = options;
			connectToken = token;
	
			/*
			 * The actual connection depends on the service, which we start and bind
			 * to here, but which we can't actually use until the serviceConnection
			 * onServiceConnected() method has run (asynchronously), so the
			 * connection itself takes place in the onServiceConnected() method
			 */
			if (mqttService == null) { // First time - must bind to the service
				Intent serviceStartIntent = new Intent(myContext,MqttService.class);
				//serviceStartIntent.setClassName(myContext, SERVICE_NAME);
				Object service = myContext.startService(serviceStartIntent);
				if (service == null) {
					IMqttActionListener listener = token.getActionCallback();
					if (listener != null) {
						listener.onFailure(token, new RuntimeException(
								"cannot start service " + SERVICE_NAME));
					}
				}
	
				// We bind with BIND_SERVICE_FLAG (0), leaving us the manage the lifecycle
				// until the last time it is stopped by a call to stopService()
				myContext.startService(serviceStartIntent);
				Log.d(TAG, "bind to mqttService");
				myContext.bindService(serviceStartIntent, serviceConnection,
						Context.BIND_AUTO_CREATE);
				
				registerReceiver(this);
			}
			else {
				
			}
	
			return token;
		}

从上面看到，其启动了一个Service，并注册了一个广播

有一个细节，起创建了一个 MqttTokenAndroid ，其用户跟踪 IMqttActionListener 回调调用，其action的过程。

<font color="red">还有，记住这里的 token，其封装了一个 客户端 传递过来的 IMqttActionListener callback 回调，并可以通过 token.getActionCallback() 获得 IMqttActionListener 实例，从而回调。</font>

抛出一个问题：

>如何设一个回调？？上文中Token的建立

> 需要考虑：
> 
> * 接口的提取
> * 装饰模式的使用
> * 结果回传，解耦  


针对服务，我们主要看，服务链接上之后的操作：

	private final class MyServiceConnection implements ServiceConnection {

		@Override
		public void onServiceConnected(ComponentName name, IBinder binder) {
			mqttService = ((MqttServiceBinder) binder).getService();
			bindedService = true;
			// now that we have the service available, we can actually
			// connect...
			Log.d(TAG, "doConnect");
			doConnect();
		}

		@Override
		public void onServiceDisconnected(ComponentName name) {
			mqttService = null;
		}
	}

调用了 

	doConnect();

	private void doConnect() {
		if (clientHandle == null) {
			//此时已与service简历链接，通过binder获取service实例，并调用getClient成员方法，

			// 注意这个 mqttService.getClient 方法，其在 service端 建立其 key-value映射
			clientHandle = mqttService.getClient(serverURI, clientId,myContext.getApplicationInfo().packageName, persistence);
		}
		mqttService.setTraceEnabled(traceEnabled);
		mqttService.setTraceCallbackId(clientHandle);
		
		// 还记得这个 connectToken吗？是上文中 说的 封装了 客户端 传递过来的 IMqttActionListener callback 回调 对象的 MqttTokenAndroid 实例。这里通过  storeToken 来获取 一个 connectToken 对象对应的 int key值（即 activityToken，其是一个int 经 String.valueof转换），并将这个int key值传入service，建立 与service的关联

		String activityToken = storeToken(connectToken);
		try {
			mqttService.connect(clientHandle, connectOptions, null,
					activityToken);
		}
		catch (MqttException e) {
			IMqttActionListener listener = connectToken.getActionCallback();
			if (listener != null) {
				listener.onFailure(connectToken, e);
			}
		}
	}

这里有两个点：

1. 获取一个clientHandler

	clientHandle = mqttService.getClient(serverURI, clientId,myContext.getApplicationInfo().packageName,	persistence);

2.调用 storeToken 获取一个 activityToken ，并将其传给 service的connect去连接

	mqttService.connect(clientHandle, connectOptions, null, activityToken);

<font color="orage">关于这两点都涉及到了与服务端的关联，具体分析在服务端处理</font>

此外，上文说过，在启动service的时候，还注册了一个广播

	@Override
	public void onReceive(Context context, Intent intent) {
		Bundle data = intent.getExtras();

		String handleFromIntent = data
				.getString(MqttServiceConstants.CALLBACK_CLIENT_HANDLE);

		if ((handleFromIntent == null)
				|| (!handleFromIntent.equals(clientHandle))) {
			return;
		}

		String action = data.getString(MqttServiceConstants.CALLBACK_ACTION);

		if (MqttServiceConstants.CONNECT_ACTION.equals(action)) {
			connectAction(data);
		}
		else if (MqttServiceConstants.MESSAGE_ARRIVED_ACTION.equals(action)) {
			messageArrivedAction(data);
		}
		else if (MqttServiceConstants.SUBSCRIBE_ACTION.equals(action)) {
			subscribeAction(data);
		}
		else if (MqttServiceConstants.UNSUBSCRIBE_ACTION.equals(action)) {
			unSubscribeAction(data);
		}
		else if (MqttServiceConstants.SEND_ACTION.equals(action)) {
			sendAction(data);
		}
		else if (MqttServiceConstants.MESSAGE_DELIVERED_ACTION.equals(action)) {
			messageDeliveredAction(data);
		}
		else if (MqttServiceConstants.ON_CONNECTION_LOST_ACTION
				.equals(action)) {
			connectionLostAction(data);
		}
		else if (MqttServiceConstants.DISCONNECT_ACTION.equals(action)) {
			disconnected(data);
		}
		else if (MqttServiceConstants.TRACE_ACTION.equals(action)) {
			traceAction(data);
		}else{
			mqttService.traceError(MqttService.TAG, "Callback action doesn't exist.");	
		}

	}

<font color="red">主要是通过 获取 intent中MqttServiceConstants.CALLBACK_ACTION 来分发动作，以MqttServiceConstants.CONNECT_ACTION为例</font>

//com.boyaa.customer.service.service.MqttAndroidClient

	private void connectAction(Bundle data) {
		//还记得这里的 connectToken吗？其是在调用MqttAndroidClient：connect方法的时候传入的IMqttActionListener构成的IMqttToken

		IMqttToken token = connectToken;
		removeMqttToken(data);
		
		simpleAction(token, data);
	}

	private void simpleAction(IMqttToken token, Bundle data) {
		if (token != null) {
			Status status = (Status) data
					.getSerializable(MqttServiceConstants.CALLBACK_STATUS);
			if (status == Status.OK) {
				((MqttTokenAndroid) token).notifyComplete();//....................
			}
			else {
				Exception exceptionThrown = (Exception) data.getSerializable(MqttServiceConstants.CALLBACK_EXCEPTION);
				((MqttTokenAndroid) token).notifyFailure(exceptionThrown);
			}
		} else {
			mqttService.traceError(MqttService.TAG, "simpleAction : token is null");	
		}
	}

//com.boyaa.customer.service.service.MqttTokenAndroid

	void notifyComplete() {
	    synchronized (waitObject) {
	      isComplete = true;
	      waitObject.notifyAll();
	      if (listener != null) {
			
			这里的 listener 就是 用户在调用 client.connect传入的 ActionListener
	        listener.onSuccess(this);//................
	      }
	    }
	  }

从广播的 的处理上，我们现在可以得知 通过 token 分发 actionListener；

> 拓展： 注意notifyComplete()方法中有一个线程同步，为什么wait()，notify()和notifyAll()必须在同步块或同步方法中调用呢？

>那时因为需要使持有 waitObject 对象的线程 获得  waitObject 的控制权；如果一个线程中 没有改对象的控制权，但调用了该对象的wait等方法时，就会报 IllegalMonitorStateException Exception。

>如何获得一个对象的 控制权呢？

> * 执行对象的某个同步实例方法。
> * 执行对象对应类的同步静态方法。
> * 执行对该对象加同步锁的同步块。


上面我们说到，在Service链接 回调 onServiceConnected 回调中，调用的doConnect方法中，调用了service.getClient方法。 这里 是 调用service端 connect的入口。


**ok,总结下 现在的流程**

1.客户端 创建 负责 进行 mqtt交互的 MqttAndroidClient实例，并将其封装成Connection，并用一个String 做key值存储在一个map中；

2.客户端 通过启动一个服务，并通过服务进行真正的 mqtt请求；

3.客户端 注册一个广播用于接收 服务端的处理情况，并将结果进行分发；

4.一个细节，因为通过启动服务（可能是跨进程），所以将客户端回调 进行 int映射，巧妙建立起与service端的联系。

5.简而言之，一套接口，两边实现，服务广播搭桥。


### Service端


1. 获取一个clientHandler

	clientHandle = mqttService.getClient(serverURI, clientId,myContext.getApplicationInfo().packageName,	persistence);

2. 调用 storeToken 获取一个 activityToken ，并将其传给 service的connect去连接

	mqttService.connect(clientHandle, connectOptions, null, activityToken);


**针对第一点：**

// com.boyaa.customer.service.service.MqttService

	private Map<String/* clientHandle */, MqttConnection/* client */> connections = new ConcurrentHashMap<String, MqttConnection>();

	....

	public String getClient(String serverURI, String clientId, String contextId,MqttClientPersistence persistence) {
		
		//clientHandle ： 服务端 链接请求代表 MqttConnection 的key值
	    String clientHandle = serverURI + ":" + clientId+":"+contextId;
	    if (!connections.containsKey(clientHandle)) {
	      MqttConnection client = new MqttConnection(this, serverURI,
	          clientId, persistence, clientHandle);
	      connections.put(clientHandle, client);
	    }
	    return clientHandle;
	  }

其主要工作，就是创建一个 MqttConnection 实例，然后以 clientHandle 为 key值，MqttConnection 实例为value值 存入一个 map中；

<font color="red">请注意 MqttConnection 持有 服务端 负责 与 server交互的 MqttAsyncClient 的实例，是服务端 链接的代表。</font>

**针对第二点：**


// com.boyaa.customer.service.service.MqttService

	  public void connect(String clientHandle, MqttConnectOptions connectOptions,
	      String invocationContext, String activityToken)
	      throws MqttSecurityException, MqttException {
			//从上文的 getClient 方法中 存入的map中获取MqttConnection对象
		  	MqttConnection client = getConnection(clientHandle);
		  	client.connect(connectOptions, invocationContext, activityToken);
			
	  }
	
	  private MqttConnection getConnection(String clientHandle) {
	    MqttConnection client = connections.get(clientHandle);
	    if (client == null) {
	      throw new IllegalArgumentException("Invalid ClientHandle");
	    }
	    return client;
	  }

看到这里，首先应该想到的是，在什么时候 从map中 remove掉  存入的 MqttConnection呢？

	  public void disconnect(String clientHandle, long quiesceTimeout,
	      String invocationContext, String activityToken) {
	    MqttConnection client = getConnection(clientHandle);
	    client.disconnect(quiesceTimeout, invocationContext, activityToken);

		//-----------------------在调disconnect的时候从map中 remove掉  存入的 MqttConnection 
	    connections.remove(clientHandle);
	
	    // the activity has finished using us, so we can stop the service
	    // the activities are bound with BIND_AUTO_CREATE, so the service will
	    // remain around until the last activity disconnects
	    stopSelf();
	  }

 上面两点，其实说白了，就是 将 客户单的 Connection 对象 映射到 服务端的 MqttConnection实例上；
并且在 服务端也保存了一个 MqttConnection对象的一个映射。

这里还有一个小细节，需要注意下

	connect(String clientHandle, MqttConnectOptions connectOptions,
	      String invocationContext, String activityToken)

对，service实例方法connect中的最后一个参数activityToken，还记得这个参数是什么吗，代表什么？

activityToken 是 客户端 MqttTokenAndroid 对象实例的映射的一个 int值；

MqttTokenAndroid 实例 有持有客户单 传递的 IMqttActionListener 实例；

也即是说，客户端 通过 activityToken 将客户端的 IMqttActionListener 传给 service端，与service端建立起了Action回调的联系。

**那么问题来了，client 通过传递 activityToken 给 service端，那么service 端是如何进行处理，并将其回传给client端，此时，客户端又将如何处理呢？**

其实上文说过，service端处理完 回调之后，通知客户端是通过 广播来做的，因此，在发送广播的 intent中会将client传过来的 activityToken 带上，交由客户端，此时客户单 从过 activityToken将找到对应的 MqttTokenAndroid 实例，并通过 MqttTokenAndroid 实例来操作 用户传入的 IMqttActionListener 监听器。

>抛出一个问题： 如何组织 建立 client端和service端 回调的传递？


截止目前，涉及到服务端这边，我们可以看到

1.通过 getClient 创建了一个service 处理mqtt请求的代表 MqttConnection对象；

2.调用 MqttConnection 对象的 connect 方法，向 mqtt服务区其 发起connect 请求 Action。  

那么，connect 成功之后 回调在那里回呢？上文分析，我们知道客户端是通过广播进行接受的，那么服务端肯定有地方发 发送广播，查阅MqttService的代码，我们发现：

	  void callbackToActivity(String clientHandle, Status status,
	      Bundle dataBundle) {
	    // Don't call traceDebug, as it will try to callbackToActivity leading
	    // to recursion.
	    Intent callbackIntent = new Intent(
	        MqttServiceConstants.CALLBACK_TO_ACTIVITY);
	    if (clientHandle != null) {
	      callbackIntent.putExtra(
	          MqttServiceConstants.CALLBACK_CLIENT_HANDLE, clientHandle);
	    }
	    callbackIntent.putExtra(MqttServiceConstants.CALLBACK_STATUS, status);
	    if (dataBundle != null) {
	      callbackIntent.putExtras(dataBundle);
	    }

		//发送广播， 一个 Broadcast
	    LocalBroadcastManager.getInstance(this).sendBroadcast(callbackIntent);
	  }


LocalBroadcastManager，称为局部通知管理器，是Android Support包提供了一个工具，是用来在同一个应用内的不同组件间发送Broadcast的。

使用LocalBroadcastManager有如下好处：

* 发送的广播只会在自己App内传播，不会泄露给其他App，确保隐私数据不会泄露
* 其他App也无法向你的App发送该广播，不用担心其他App会来搞破坏
* 比系统全局广播更加高效

总之，这种通知的好处是安全性高，效率也高，适合局部通信。

ok，上面，我们看到，服务端的 代表 mqtt请求对象 MqttConnection 的建立、connect动作的出发、以及服务端回调的处理。

接下来，我们就要继续探究下 服务端 具体是怎么处理 mqtt请求动作的。

#### 继续探究

#### 代表service端 MqttConnection对象 的建立

从上文得知 MqttConnection 对象 是在 MqttService:getClient()方法中创建的。
// com.boyaa.customer.service.service.MqttConnection

	MqttConnection(MqttService service, String serverURI, String clientId,
			MqttClientPersistence persistence, String clientHandle) {
		this.serverURI = serverURI.toString();
		this.service = service;
		this.clientId = clientId;
		this.persistence = persistence;
		this.clientHandle = clientHandle;
	}

其中 ，

//com.boyaa.customer.service.service.MqttAndroidClient

	String clientHandle = serverURI + ":" + clientId+":"+contextId;
	contextId = myContext.getApplicationInfo().packageName；

ok，也就是说 ，MqttConnection 持有 一个 MqttService 对象。

还有一个细节

	class MqttConnection implements MqttCallback{}


MqttCallback 又是什么呢？

>Enables an application to be notified when asynchronous events related to the client occur.

当事件处理完之后，异步通知client，其实通过 setCallback 方法设置的。

	IMqttClient.setCallback(MqttCallback)

#### 客户端 MqttCallback 回调的设置

在客户端相关逻辑整理完之后，我们说过，一套接口，两边实现，那么针对 IMqttClient.setCallback(MqttCallback) 这个，在客户端是如何实现的呢？而服务端又是如何与之进行交互的呢？

其实也 ActionListener逻辑一样：

//com.boyaa.customer.service.service.MqttAndroidClient

	public void setCallback(MqttCallback callback) {
		this.callback = callback;
	}


	private void messageArrivedAction(Bundle data) {
		if (callback != null) {
			try {
				if (messageAck == Ack.AUTO_ACK) {
					callback.messageArrived(destinationName, message);
					mqttService.acknowledgeMessageArrival(clientHandle, messageId);
				}
				else {
					message.messageId = messageId;
					callback.messageArrived(destinationName, message);
				}
			}
			catch (Exception e) {
				// Swallow the exception
			}
		}
	}

messageArrivedAction 方法是通过 接收到 service发送的广播来进行分发的。

上面就是 客户端端 对 MqttCallback 回调的设置，那么服务端呢？

#### 服务端 MqttCallback 回调的设置

服务端 MqttCallback 回调的设置 也是通过 

	IMqttClient.setCallback(MqttCallback)

来进行设置的，只不过服务端实现 MqttCallback 接口的实例是 我们上文说的 MqttConnection类。

分析到这一点后，我们继续 探究 服务端 发起 mqtt 链接请求的过程。

#### MqttConnection connect方法的调用

上文说到，服务端通过 getClient建立 MqttConnection 实例，之后，通过调用 MqttConnection 的 connect方法去请求Mqtt链接。

	public void connect(MqttConnectOptions options, String invocationContext,
			String activityToken) {
		
		// step1: 设置广播intent，并设置 广播的Action，便于client 识别
		// 将 MqttServiceConstants.CALLBACK_ACTION 设置为 MqttServiceConstants.CONNECT_ACTION
		connectOptions = options;
		reconnectActivityToken = activityToken;

		service.traceDebug(TAG, "Connecting {" + serverURI + "} as {"+ clientId + "}");
		final Bundle resultBundle = new Bundle();
		resultBundle.putString(MqttServiceConstants.CALLBACK_ACTIVITY_TOKEN,
				activityToken);
		resultBundle.putString(
				MqttServiceConstants.CALLBACK_INVOCATION_CONTEXT,
				invocationContext);
		resultBundle.putString(MqttServiceConstants.CALLBACK_ACTION,
				MqttServiceConstants.CONNECT_ACTION);

				
		try {
			// 这里是 序列化的事情，我们暂且不考虑
			....

			// step2: 创建 服务端 IMqttActionListener 实例
			IMqttActionListener listener = new MqttConnectionListener(
					resultBundle) {

				@Override
				public void onSuccess(IMqttToken asyncActionToken) {
					doAfterConnectSuccess(resultBundle);
					service.traceDebug(TAG, "connect success!");
				}

				@Override
				public void onFailure(IMqttToken asyncActionToken,
						Throwable exception) {
					resultBundle.putString(
							MqttServiceConstants.CALLBACK_ERROR_MESSAGE,
							exception.getLocalizedMessage());
					resultBundle.putSerializable(
							MqttServiceConstants.CALLBACK_EXCEPTION, exception);
					service.traceError(TAG,
							"connect fail, call connect to reconnect.reason:"
									+ exception.getMessage());

					doAfterConnectFail(resultBundle);

				}
			};
			
			if (myClient != null) { // 除此请求 myClient都是null
				if (isConnecting ) {
					service.traceDebug(TAG,
							"myClient != null and the client is connecting. Connect return directly.");
					service.traceDebug(TAG,"Connect return:isConnecting:"+isConnecting+".disconnected:"+disconnected);
					return;
				}else if(!disconnected){
					service.traceDebug(TAG,"myClient != null and the client is connected and notify!");
					doAfterConnectSuccess(resultBundle);
				}
				else {					
					service.traceDebug(TAG, "myClient != null and the client is not connected");
					service.traceDebug(TAG,"Do Real connect!");
					setConnectingState(true);
					myClient.connect(connectOptions, invocationContext, listener);
				}
			}
			
			// if myClient is null, then create a new connection
			else {
				// step3: 创建 MqttAsyncClient 实例, setCallback(MqttCallback),并调用connect方法去连接Mqtt 服务器

				myClient = new MqttAsyncClient(serverURI, clientId,
						persistence, new AlarmPingSender(service));
				myClient.setCallback(this);

				service.traceDebug(TAG,"Do Real connect!");
				setConnectingState(true);
				myClient.connect(connectOptions, invocationContext, listener);
			}
		} catch (Exception e) {
			handleException(resultBundle, e);
		}
	}

这段代码有点长，但整体来说，MqttConnection的connect请求其实实质是交给 MqttAsyncClient 去connect。

上面代码 重点 在于代码中的 注释 所标出来的 step1、step2、step3.

step1: 建立广播 intent，设置广播Action

step2: 创建 IMqttActionListener 实例，并在调用 MqttAsyncClient:connect 方法的时候传入

step3: 创建 MqttAsyncClient 实例，并setCallback()

在进行下一步分析之前，先区分下 MqttCallback 和 IMqttActionListener，暂且理解如下：

* MqttCallback 类似 监听器，监听处理后的结果；
* IMqttActionListener 类似 动作监听，即 发出的动作是否完成，比如connect完成之后 回调 IMqttActionListener

OK，经过前边分析，我们知道，service 通过 广播 将 回调处理 传递给 client端。

因此，我们得知：

* 经过 step1，我们确认 该广播的 Callback_action为 MqttServiceConstants.CONNECT_ACTION，所以，client通过该值可以确认为 Connect 回调。
* 此外，我们分别将在 IMqttActionListener 以及 callback中 设置Intent 的状态，告诉客户端相关细节。

举个列子：

	public void messageArrived(String topic, MqttMessage message)
			throws Exception {

		service.traceDebug(TAG,
				"messageArrived(" + topic + ",{" + message.toString() + "})");

		String messageId = service.messageStore.storeArrived(clientHandle,
				topic, message);
		
		// 将 message Parcelable化，然后存入Bundle中进行传递
		Bundle resultBundle = messageToBundle(messageId, topic, message);

		//设置 CALLBACK_ACTION 为 MESSAGE_ARRIVED_ACTION
		resultBundle.putString(MqttServiceConstants.CALLBACK_ACTION,
				MqttServiceConstants.MESSAGE_ARRIVED_ACTION);
		resultBundle.putString(MqttServiceConstants.CALLBACK_MESSAGE_ID,
				messageId);

		// 发送广播
		service.callbackToActivity(clientHandle, Status.OK, resultBundle);
				
	}

ok，总结下，目前来看 这一层貌似已经解耦

* 通过设置 广播的Action，确定做的是哪一件事，并在service结果处理完之后广播通知客户端；
* 通过调用 MqttAsyncClient 的connect方法去连接 Mqtt 服务器。


我们继续下一步。

#### MqttAsyncClient connect方法的调用

//com.boyaa.customer.service.client.mqttv3.MqttAsyncClient

	public MqttAsyncClient(String serverURI, String clientId, MqttClientPersistence persistence, MqttPingSender pingSender) {
		final String methodName = "MqttAsyncClient";		
		this.serverURI = serverURI;
		this.clientId = clientId;
		this.comms = new ClientComms(this, this.persistence, pingSender);
		this.topics = new Hashtable();
	}	

	public IMqttToken connect(MqttConnectOptions options, Object userContext, IMqttActionListener callback){
		
		comms.setNetworkModules(createNetworkModules(serverURI, options));

		// Insert our own callback to iterate through the URIs till the connect succeeds
		MqttToken userToken = new MqttToken(getClientId());
		ConnectActionListener connectActionListener = new ConnectActionListener(this, persistence, comms, options, userToken, userContext, callback);
		userToken.setActionCallback(connectActionListener);
		userToken.setUserContext(this);

		comms.setNetworkModuleIndex(0);
		connectActionListener.connect();

		return userToken;
	}

这里出现了几个陌生的 对象：

1. MqttPingSender :暂且不用看

> Default ping sender implementation on Android. It is based on AlarmManager

2. ClientComms ：真正用于 处理链接 Mqtt 的对象
3. ConnectActionListener，对IMqttActionListener 进行再封装，装饰这模式，对应 Connect 这一动作 抽象出来的对象。

这里有几个 关键的点：

* ClientComms 对象创建的时候 持有 MqttAsyncClient 实例；
>Handles client communications with the server.  Sends and receives MQTT V3 messages.

* comms.setNetworkModules(createNetworkModules(serverURI, options));
> NetworkModule 一个针对Socket链接的接口抽象

* ConnectActionListener 创建，并调用connect方法。
> This class handles the connection of the AsyncClient to one of the available URLs,简单来说，是对当前tcp请求的一次抽象。

//com.boyaa.customer.service.client.mqttv3.MqttAsyncClient

	private NetworkModule createNetworkModule(String address, MqttConnectOptions options) throws MqttException, MqttSecurityException {	
		String shortAddress = address.substring(6);
		String host = getHostName(shortAddress);
		int port = getPort(shortAddress, 1883);
		SocketFactory factory = options.getSocketFactory();
		if (factory == null) {
				factory = SocketFactory.getDefault();
		}
		NetworkModule netModule = new TCPNetworkModule(factory, host, port, clientId);
		((TCPNetworkModule)netModule).setConnectTimeout(options.getConnectionTimeout());
		...
		return netModule;
	}

// com.boyaa.customer.service.client.mqttv3.internal.NetworkModule

	public interface NetworkModule {
		public void start() throws IOException, MqttException;
		
		public InputStream getInputStream() throws IOException;
		
		public OutputStream getOutputStream() throws IOException;
		
		public void stop() throws IOException;
	}

<font color="red">**隐藏很深的Socket链接终于露出点马脚**</font>

> 这里抛出一个问题：如何针对Socket请求做封装？

总结下，然后带装而发

* 通过 createNetworkModule 创建一个 代表Socket链接的对象 NetworkModule ，这里创建了 TCPNetworkModule ，这里也是我们刚开始找的 切入点；
* 通过建立 代表 本次链接请求的 ConnectActionListener 进行链接；其构造函数中传入MqttToken用于跟踪ActionListener，传入ClientComms，实际操作mqtt链接（因为其 setNetworkModules ,也就是说 ，拥有Socket）
* ClientComms 持有Socket,并且持有 MqttCallback 回调

// com.boyaa.customer.service.client.mqttv3.MqttAsyncClient

	public void setCallback(MqttCallback callback) {
		comms.setCallback(callback);
	}
这里的 callback 就是 MqttConnection 对象。

这里我们做个猜想，我们知道 ClientComms 持有 Socket,那么应该 真正的Socket 请求是由 ClientComms 发起的，此外，我们知道 ConnectActionListener 持有 ClientComms 实例。

//com.boyaa.customer.service.client.mqttv3.internal.ConnectActionListener

	  public void connect() throws MqttPersistenceException {

		//这里 创建了一个 token
	    MqttToken token = new MqttToken(client.getClientId());
	    token.setActionCallback(this);
	    token.setUserContext(this);
	    
	    if (options.getMqttVersion() == MqttConnectOptions.MQTT_VERSION_DEFAULT) {
	      options.setMqttVersion(MqttConnectOptions.MQTT_VERSION_3_1_1);
	    }
	
	    try {

		// 果不其然，调用 ClientComms 的 connect,并且 将创建的 token 传入，注意，这里的token:setActionCallback的是当前 ConnectActionListener 实例

	      comms.connect(options, token);
	    }
	    catch (MqttException e) {
	      onFailure(token, e);
	    }
	  }

	//并且在 connect success回调中 调用 userCallback.onSuccess
	//userCallback就是在MqttConnection调用connect的时候传入的IMqttActionListener，然后在通过广播透传客户端。

	  public void onSuccess(IMqttToken token) {
		if (originalMqttVersion == MqttConnectOptions.MQTT_VERSION_DEFAULT) {
	      options.setMqttVersion(MqttConnectOptions.MQTT_VERSION_DEFAULT);
		}
	    userToken.internalTok.markComplete(token.getResponse(), null);
	    userToken.internalTok.notifyComplete();
	
	    if (userCallback != null) {
	      userToken.setUserContext(userContext);
	      userCallback.onSuccess(userToken);
	    }
	  }

#### ClientComms 的connect方法调用

终于到了ClientComms 的connect方法了，较之前，我们猜想，真正的Socket链接会在 ClientComms 中发生。

//com.boyaa.customer.service.client.mqttv3.internal.ClientComms

	public void connect(MqttConnectOptions options, MqttToken token) throws MqttException {
		final String methodName = "connect";
		synchronized (conLock) {
			if (isDisconnected() && !closePending) {
				//@TRACE 214=state=CONNECTING
				log.fine(CLASS_NAME,methodName,"214");

				conState = CONNECTING;

				this.conOptions = options;
				
				//建立 MqttConnect 链接对象，设置 用户名、用户密码等信息
				MqttConnect connect = new MqttConnect(client.getClientId(),
						options.getMqttVersion(),
						options.isCleanSession(),
						options.getKeepAliveInterval(),
						options.getUserName(),
						options.getPassword(),
						options.getWillMessage(),
						options.getWillDestination());

				this.clientState.setKeepAliveSecs(options.getKeepAliveInterval());
				this.clientState.setCleanSession(options.isCleanSession());

				tokenStore.open();

				//链接线程
				ConnectBG conbg = new ConnectBG(this, token, connect);
				conbg.start();
			}
		}
	}

创建一个 MqttConnect 对象，其封装了 链接请求的相关信息，然后创建一个处理 请求消息的线程对象 ConnectBG，在work线程中进行处理。

记得，在 ConnectBG 还传入了 一个 MqttToken 对象，此创建是在 ConnectActionListener 的connect方法中，并且

	    MqttToken token = new MqttToken(client.getClientId());
	    token.setActionCallback(this);
	    token.setUserContext(this);

这个this 是 ConnectActionListener，所以，后续猜想会调用，出发回调动作。这里标记下 

	token.getActionCallback().onXXX(asyncActionToken)

ok，思路拉回来，再来看看 ClientComms 的 处理 MqttConnect 的线程执行。

MqttConnect 其实是一个 类型为 MqttWireMessage.MESSAGE_TYPE_CONNECT 的 MqttWireMessage，

MqttWireMessage：代表一个 Mqtt 消息

>An on-the-wire representation of an MQTT message.

//com.boyaa.customer.service.client.mqttv3.internal.ClientComms:ConnectBG

		public void run() {
			final String methodName = "connectBG:run";
			MqttException mqttEx = null;
			//@TRACE 220=>
			log.fine(CLASS_NAME, methodName, "220");

			try {
				// Reset an exception on existing delivery tokens.
				// This will have been set if disconnect occured before delivery was
				// fully processed.
				MqttDeliveryToken[] toks = tokenStore.getOutstandingDelTokens();
				for (int i=0; i<toks.length; i++) {
					toks[i].internalTok.setException(null);
				}

				// Save the connect token in tokenStore as failure can occur before send
				tokenStore.saveToken(conToken,conPacket);

				// Connect to the server at the network level e.g. TCP socket and then
				// start the background processing threads before sending the connect
				// packet.
				NetworkModule networkModule = networkModules[networkModuleIndex];
				networkModule.start();
				receiver = new CommsReceiver(clientComms, clientState, tokenStore, networkModule.getInputStream());
				receiver.start("MQTT Rec: "+getClient().getClientId());
				sender = new CommsSender(clientComms, clientState, tokenStore, networkModule.getOutputStream());
				sender.start("MQTT Snd: "+getClient().getClientId());
				callback.start("MQTT Call: "+getClient().getClientId());				
				internalSend(conPacket, conToken);
			} catch (MqttException ex) {
				//@TRACE 212=connect failed: unexpected exception
				log.fine(CLASS_NAME, methodName, "212", null, ex);
				mqttEx = ex;
			} catch (Exception ex) {
				//@TRACE 209=connect failed: unexpected exception
				log.fine(CLASS_NAME, methodName, "209", null, ex);
				mqttEx =  ExceptionHelper.createMqttException(ex);
			}

			if (mqttEx != null) {
				shutdownConnection(conToken, mqttEx);
			}
		} 

看到了没,
	
	//建立Socket链接
	NetworkModule networkModule = networkModules[networkModuleIndex];
	networkModule.start();
	
	//通过 networkModule.getInputStream() 处理 从服务器接收到的消息
	receiver = new CommsReceiver(clientComms, clientState, tokenStore, networkModule.getInputStream());
	receiver.start("MQTT Rec: "+getClient().getClientId());
	
	//通过 networkModule.getOutputStream() 处理 从向服务器发送的消息
	sender = new CommsSender(clientComms, clientState, tokenStore, networkModule.getOutputStream());
	sender.start("MQTT Snd: "+getClient().getClientId());

千盼万盼，终于看到 直接进行 Socket的请求了，赤裸裸的诱惑啊，不过这里有个 小细节，我们看到，这里都通过 创建一个Thread对象，封装networkModule的getInput和getOutput，也就是说，将Socket的输入输入分别交给两个 work线程来处理。

那么，这两个线程是这么关联起来的呢？我们看到每一个线程都持有 

* clientComms实例

* tokenStore : CommsTokenStore, 存储Token 于 Message，也就是说，可以通过Message找到Token，从而找到ConnectActionListener，然后callback ActionListener。

> Provides a "token" based system for storing and tracking actions across multiple threads. 

* clientState : ClientState,掌握消息的状态
>The core of the client, which holds the state information for pending and in-flight messages.

ok，因为我们现在处理的 connect请求，也就是说要向服务器发送MqttConn消息，从上文，我们得知，向服务器发送消息 是CommsSender来处理的，为什么呢，因为它持有 networkModule.getOutputStream()。哈哈哈

#### 处理 Socket 发送消息 CommsSende

// com.boyaa.customer.service.client.mqttv3.internal.CommsSender

	public class CommsSender implements Runnable{}

我们发现 CommsSender implements Runnable接口，也就是说是一个 Task，为什么这里不直接 extends Thread呢？猜想， 实现 Runnable 更灵活些，将处理 deliver server的message 封装成一个Task更合理些，并且，可以在 CommsSender 创建一个线程 持有自身，可以控制是否start等。

因此，在后续 对于需要在 一个子线程中进行处理的事情，我们可以 封装成一个Runnable Task，然后在Runnable Task中进行处理。

言归正传。

// com.boyaa.customer.service.client.mqttv3.internal.CommsSender

	public void run() {
		final String methodName = "run";
		MqttWireMessage message = null;
		while (running && (out != null)) {
			try {
				//注意这里！！！！！，这是一个阻塞方法
				message = clientState.get();
				if (message != null) {
					//@TRACE 802=network send key={0} msg={1}
					log.fine(CLASS_NAME,methodName,"802", new Object[] {message.getKey(),message});

					// MqttAck:Abstract super-class of all acknowledgement messages.
					// MqttConnect不是 MqttAck 消息
					if (message instanceof MqttAck) {
						out.write(message);
						out.flush();
					} else {

						//这里前文说过，tokenStore 以message的key值为key，存入Token
						MqttToken token = tokenStore.getToken(message);
						// While quiescing the tokenstore can be cleared so need 
						// to check for null for the case where clear occurs
						// while trying to send a message.
						if (token != null) {
							synchronized (token) {
								//想Mqtt 服务器发送消息
								out.write(message);
								try {
									out.flush();
								} catch (IOException ex) {
									// The flush has been seen to fail on disconnect of a SSL socket
									// as disconnect is in progress this should not be treated as an error
									if (!(message instanceof MqttDisconnect)) {
										throw ex;
									}
								}
								//处理回调
								clientState.notifySent(message);
							}
						}
					}
				} else { // null message
					//@TRACE 803=get message returned null, stopping}
					log.fine(CLASS_NAME,methodName,"803");

					running = false;
				}
			} catch (MqttException me) {
				handleRunException(message, me);
			} catch (Exception ex) {		
				handleRunException(message, ex);	
			}
		} // end while
		
		//@TRACE 805=<
		log.fine(CLASS_NAME, methodName,"805");

	}

MqttAck:确认消息
> Abstract super-class of all acknowledgement messages.

上面说到 

	message = clientState.get();

是一个 阻塞方法，clientState 是何方神圣，其是 ClientState 实例，掌握着消息的动态，那么，下来就让我们一睹 clientState.get() 的芳颜。

// com.boyaa.customer.service.client.mqttv3.internal.ClientState

	protected MqttWireMessage get() throws MqttException {
		final String methodName = "get";
		MqttWireMessage result = null;

		synchronized (queueLock) {
			while (result == null) {
				
				// If there is no work wait until there is work.
				// If the inflight window is full and no flows are pending wait until space is freed.
				// In both cases queueLock will be notified.
				if ((pendingMessages.isEmpty() && pendingFlows.isEmpty()) || 
					(pendingFlows.isEmpty() && actualInFlight >= this.maxInflight)) {
					try {
						//@TRACE 644=wait for new work or for space in the inflight window 
						log.fine(CLASS_NAME,methodName, "644");						
 
						//queueLock wait,是的，该方法需要 queueLock notify换新。
						queueLock.wait();
						
						//@TRACE 647=new work or ping arrived 
						log.fine(CLASS_NAME,methodName, "647");
					} catch (InterruptedException e) {
					}
				}				
								
				// Now process any queued flows or messages
				if (!pendingFlows.isEmpty()) {
					// Process the first "flow" in the queue
					result = (MqttWireMessage)pendingFlows.remove(0);
					if (result instanceof MqttPubRel) {
						inFlightPubRels++;

						//@TRACE 617=+1 inflightpubrels={0}
						log.fine(CLASS_NAME,methodName,"617", new Object[]{new Integer(inFlightPubRels)});
					}
		
					checkQuiesceLock();
				} else if (!pendingMessages.isEmpty()) {
					// If the inflight window is full then messages are not 
					// processed until the inflight window has space. 
					if (actualInFlight < this.maxInflight) {
						// The in flight window is not full so process the 
						// first message in the queue
						result = (MqttWireMessage)pendingMessages.elementAt(0);
						pendingMessages.removeElementAt(0);
						actualInFlight++;
	
						//@TRACE 623=+1 actualInFlight={0}
						log.fine(CLASS_NAME,methodName,"623",new Object[]{new Integer(actualInFlight)});
					} else {
						//@TRACE 622=inflight window full
						log.fine(CLASS_NAME,methodName,"622");				
					}
				}			
			}
		}
		return result;
	}

* queueLock.wait()：等待其他线程 唤醒
* 唤醒之后 从 pendingFlows 或者 pendingMessages 中获取消息对象
* 进入wait条件是 pendingMessages.isEmpty() && pendingFlows.isEmpty()，并且 通过while（result == null）来循环监听 是否notify，避免 假唤醒。

那么问题来了，pendingMessages 和 pendingFlows 又是什么，貌似看是一个 容器，那么什么会后往 该容器中 存入对象呢？只要往该容器存入对象之后，其就不为empty，那么就可以获得该Message进行发送了。

我们搜索一下 这两个容器类，发现

	volatile private Vector pendingMessages;
	volatile private Vector pendingFlows;


// com.boyaa.customer.service.client.mqttv3.internal.ClientState

	public void send(MqttWireMessage message, MqttToken token) throws MqttException {
		final String methodName = "send";
		if (message.isMessageIdRequired() && (message.getMessageId() == 0)) {
			message.setMessageId(getNextMessageId());
		}
		if (token != null ) {
			try {
				token.internalTok.setMessageID(message.getMessageId());
			} catch (Exception e) {
			}
		}
			
		if (message instanceof MqttConnect) {
				synchronized (queueLock) {
					// Add the connect action at the head of the pending queue ensuring it jumps
					// ahead of any of other pending actions.
					tokenStore.saveToken(token, message);
					pendingFlows.insertElementAt(message,0);
					queueLock.notifyAll();
				}
			} 	
	}

发送是在 ClientComms ： ConnectBG 线程中，并且将消息 存入 pendingFlows 中，唤醒 queueLock monitor

获取是在 CommsSender 线程中，wait条件是 pendingFlows为 empty。

也就是说 ，处理 connect 请求 是在 ConnectBG 线程中，然后在该线程中 将 out 和 in 两个操作 有分别放在子线程中进行处理。 其同步是交由 ClientState 来进行。ClientState其掌握着消息的动向。

那么，MqttConnect消息时什么时候发送过去的呢？

其实，上文已提到，是在 ConnectBG 线程中 ，通过调用

//com.boyaa.customer.service.client.mqttv3.internal.ClientComms:ConnectBG

	void internalSend(MqttWireMessage message, MqttToken token) throws MqttException {
		final String methodName = "internalSend";
		//@TRACE 200=internalSend key={0} message={1} token={2}
		log.fine(CLASS_NAME, methodName, "200", new Object[]{message.getKey(), message, token});

		if (token.getClient() == null ) {
			// Associate the client with the token - also marks it as in use.
			token.internalTok.setClient(getClient());
		} else {
			// Token is already in use - cannot reuse
			//@TRACE 213=fail: token in use: key={0} message={1} token={2}
			log.fine(CLASS_NAME, methodName, "213", new Object[]{message.getKey(), message, token});

			throw new MqttException(MqttException.REASON_CODE_TOKEN_INUSE);
		}

		try {
			// Persist if needed and send the message
			this.clientState.send(message, token);
		} catch(MqttException e) {
			if (message instanceof MqttPublish) {
				this.clientState.undo((MqttPublish)message);
			}
			throw e;
		}
	}

该 message就是 MqttConnect消息。我们发现 最终是调用 this.clientState.send(message, token); 去发送消息，处理同步，并唤醒正在wait的Sender，然后向服务器 发送消息。

ok，消息 发送完毕，回调如何处理呢？还记得 传入给 ConnectBG 的token吗？其是 含有 ConnectionListener的Token。

#### 最后一关，回调处理

为了看回调的处理，我们需要 重新看下 ClientComms的构造方法

//com.boyaa.customer.service.client.mqttv3.internal.ClientComms

	public ClientComms(IMqttAsyncClient client, MqttClientPersistence persistence, MqttPingSender pingSender) throws MqttException {
		this.conState = DISCONNECTED;
		this.client 	= client;
		this.persistence = persistence;
		this.pingSender = pingSender;
		this.pingSender.init(this);
		
		this.tokenStore = new CommsTokenStore(getClient().getClientId());
		this.callback 	= new CommsCallback(this);
		this.clientState = new ClientState(persistence, tokenStore, this.callback, this, pingSender);

		callback.setClientState(clientState);
		log.setResourceName(getClient().getClientId());
	}

对，看到这里有一个 CommsCallback 对象，其持有 ClientComms 当前实例，并且 setClientState(clientState);
此外，在ConnectBG线程中

//com.boyaa.customer.service.client.mqttv3.internal.ClientComms:ConnectBG

		public void run() {
			。。。。。
			callback.start("MQTT Call: "+getClient().getClientId());	

			。。。。。
	    }

这个时候，我们就得到 CommsCallback 回调任务中 走一遭了。

我们现在知道，该 CommsCallback 持有一个 ClientState ，而ClientState 又持有一个 CommsTokenStore， CommsTokenStore 有存入了 Message:Token的键值关系。

// com.boyaa.customer.service.client.mqttv3.internal.CommsCallback:run

	public void run() {
		final String methodName = "run";
		while (running) {
			try {
				// If no work is currently available, then wait until there is some...
				try {
					synchronized (workAvailable) {
						if (running && messageQueue.isEmpty()
								&& completeQueue.isEmpty()) {
							// @TRACE 704=wait for workAvailable
							log.fine(CLASS_NAME, methodName, "704");
							workAvailable.wait();
						}
					}
				} catch (InterruptedException e) {
				}

				if (running) {
					// Check for deliveryComplete callbacks...
					MqttToken token = null;
					synchronized (completeQueue) {
					    if (!completeQueue.isEmpty()) {
						    // First call the delivery arrived callback if needed
						    token = (MqttToken) completeQueue.elementAt(0);
						    completeQueue.removeElementAt(0);
					    }
					}
					if (null != token) {
						// 注意这个
						handleActionComplete(token);
					}
					
					// Check for messageArrived callbacks...
					MqttPublish message = null;
					synchronized (messageQueue) {
					    if (!messageQueue.isEmpty()) {
						    // Note, there is a window on connect where a publish
						    // could arrive before we've
						    // finished the connect logic.
							message = (MqttPublish) messageQueue.elementAt(0);

							messageQueue.removeElementAt(0);
					    }
					}
					if (null != message) {

						// 注意这个
						handleMessage(message);
					}
				}

				if (quiescing) {
					clientState.checkQuiesceLock();
				}
				
			} catch (Throwable ex) {
				// Users code could throw an Error or Exception e.g. in the case
				// of class NoClassDefFoundError
				// @TRACE 714=callback threw exception
				log.fine(CLASS_NAME, methodName, "714", null, ex);
				running = false;
				clientComms.shutdownConnection(null, new MqttException(ex));
				
			} finally {
			    synchronized (spaceAvailable) {
                    // Notify the spaceAvailable lock, to say that there's now
                    // some space on the queue...

                    // @TRACE 706=notify spaceAvailable
                    log.fine(CLASS_NAME, methodName, "706");
                    spaceAvailable.notifyAll();
                }
			}
		}
	}


	private void handleMessage(MqttPublish publishMessage)
			throws MqttException, Exception {
		final String methodName = "handleMessage";
		// If quisecing process any pending messages. 
		if (mqttCallback != null) {
			String destName = publishMessage.getTopicName();

			// @TRACE 713=call messageArrived key={0} topic={1}
			log.fine(CLASS_NAME, methodName, "713", new Object[] { 
					new Integer(publishMessage.getMessageId()), destName });
			
			//回传客户端
			mqttCallback.messageArrived(destName, publishMessage.getMessage());

			if (publishMessage.getMessage().getQos() == 1) {
				this.clientComms.internalSend(new MqttPubAck(publishMessage),
						new MqttToken(clientComms.getClient().getClientId()));
			} else if (publishMessage.getMessage().getQos() == 2) {
				this.clientComms.deliveryComplete(publishMessage);
				MqttPubComp pubComp = new MqttPubComp(publishMessage);
				this.clientComms.internalSend(pubComp, new MqttToken(clientComms.getClient().getClientId()));
			}
		}
	}

也即是说 ，客户端 设置的  MqttCallback 回调是在 CommsCallback 的handleMessage 进行回调处理的；

至于，Token的分发，是在 com.boyaa.customer.service.client.mqttv3.internal.CommsReceiver 接收到消息之后，通知CommsCallback ，从而使得 callback的run方法 notify。调用handleActionComplete（Token）进行分发。

// com.boyaa.customer.service.client.mqttv3.internal.CommsCallback

	private void handleActionComplete(MqttToken token)
			throws MqttException {
		final String methodName = "handleActionComplete";
		synchronized (token) {
			// @TRACE 705=callback and notify for key={0}
			log.fine(CLASS_NAME, methodName, "705",	new Object[] { token.internalTok.getKey() });
			
			// Unblock any waiters and if pending complete now set completed
			token.internalTok.notifyComplete();
			
 			if (!token.internalTok.isNotified()) {
 				// If a callback is registered and delivery has finished 
 				// call delivery complete callback. 
				if ( mqttCallback != null 
					&& token instanceof MqttDeliveryToken 
					&& token.isComplete()) {
						mqttCallback.deliveryComplete((MqttDeliveryToken) token);
				}
				// Now call async action completion callbacks
				fireActionEvent(token);
			}
			
			// Set notified so we don't tell the user again about this action.
 			if ( token.isComplete() ){
 			   if ( token instanceof MqttDeliveryToken || token.getActionCallback() instanceof IMqttActionListener ) {
 	                token.internalTok.setNotified(true);
 	            }
 			}
			

			if (token.isComplete()) {
				// Finish by doing any post processing such as delete 
				// from persistent store but only do so if the action
				// is complete
				clientState.notifyComplete(token);
			}
		}
	}

	public void fireActionEvent(MqttToken token) {
		final String methodName = "fireActionEvent";

		if (token != null) {
			IMqttActionListener asyncCB = token.getActionCallback();
			if (asyncCB != null) {
				if (token.getException() == null) {
					// @TRACE 716=call onSuccess key={0}
					log.fine(CLASS_NAME, methodName, "716",
							new Object[] { token.internalTok.getKey() });
					asyncCB.onSuccess(token);
				} else {
					// @TRACE 717=call onFailure key {0}
					log.fine(CLASS_NAME, methodName, "716",
							new Object[] { token.internalTok.getKey() });
					asyncCB.onFailure(token, token.getException());
				}
			}
		}
	}

如上，在 fireActionEvent 中调用 token.getActionCallback() 获得Token，并且调用 asyncCB.onSuccess(token);

这里的 asyncCB就是ConnectActionListener，然后在 ConnectActionListener的onSuccess 调用其 装饰的 IMqttActionListener对象的 onSuccess,这个 IMqttActionListener对象 MqttConnection中connect方法中创建的 IMqttActionListener对象。

在 MqttConnection中connect方法中创建的 IMqttActionListener对象 的onSuccess回调中，通过 发送 MqttServiceConstants.CONNECT_ACTION的广播，通知 客户端 链接成功。


！！！！！！！至此，整个connect的过程就分析完了。

总结一下：

* MqttConnection是service端的上层抽象，调用其connect 最终交由 MqttAsyncClient 的 worker 线程来进行具体的 MQTT Socket交互。
* NetworkModule是对Socket链接的一次抽象；
* CommsSender 和 CommsReceiver 是对 Socket 发送和接受消息 处理的 一个任务抽象；
* CommsCallback 处理整个服务器端 处理的回调
* Token用于跟踪回调
* ClientState 用于处理消息的动向，主要处理 CommsSender 与 CommsCallback 和 CommsReceiver 与   CommsCallback 的同步。

简而言之：

<font size="4" color ="red">**一套接口，两边实现，服务广播搭桥**</font>
