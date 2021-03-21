# 经典网络结构的pytorch实现

经过了一年左右的理论学习，终于到了实践环节。现阶段目的是写一个对分割后的车牌字符进行分类的分类网络。因此用pytorch对几种经典的网络结构进行复现并测试效果。

## AlexNet

AlexNet论文原文：[ImageNet Classification with Deep Convolutional Neural Networks](https://proceedings.neurips.cc/paper/2012/file/c399862d3b9d6b76c8436e924a68c45b-Paper.pdf)

AlexNet结构图：

![image-20210205220838444](C:\Users\xieyucheng\AppData\Roaming\Typora\typora-user-images\image-20210205220838444.png)

可以看出AlexNet有5个卷积层和3个全连接层。总共8层的深度，复现起来还是比较容易的。

```python
import torch
import torch.nn as nn
import torchvision

class AlexNetbase(nn.Module):
    def __init__(self,num_classes=65):
        super(AlexNetbase,self).__init__()
        self.feature_extraction = nn.Sequential(
            nn.Conv2d(in_channels=3,out_channels=96,kernel_size=11,stride=4,padding=2,bias=False),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=3,stride=2,padding=0),
            nn.Conv2d(in_channels=96,out_channels=192,kernel_size=5,stride=1,padding=2,bias=False),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=3,stride=2,padding=0),
            nn.Conv2d(in_channels=192,out_channels=384,kernel_size=3,stride=1,padding=1,bias=False),
            nn.ReLU(inplace=True),
            nn.Conv2d(in_channels=384,out_channels=256,kernel_size=3,stride=1,padding=1,bias=False),
            nn.ReLU(inplace=True),
            nn.Conv2d(in_channels=256,out_channels=256,kernel_size=3,stride=1,padding=1,bias=False),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=3, stride=2, padding=0),
        )
        self.classifier = nn.Sequential(
            nn.Dropout(p=0.5),
            nn.Linear(in_features=256*6*6,out_features=4096),
            nn.ReLU(inplace=True),
            nn.Dropout(p=0.5),
            nn.Linear(in_features=4096, out_features=4096),
            nn.ReLU(inplace=True),
            nn.Linear(in_features=4096, out_features=num_classes),
        )
    def forward(self,x):
        x = self.feature_extraction(x)
        x = x.view(x.size(0), -1)
        x = self.classifier(x)
        return x

def AlexNet():
  return AlexNetbase()
```





## VggNet

VggNet论文原文：[VERY DEEP CONVOLUTIONAL NETWORKS FOR LARGE-SCALE IMAGE RECOGNITION](https://arxiv.org/pdf/1409.1556.pdf%20http://arxiv.org/abs/1409.1556.pdf)

结构图：

![image-20210205221417030](C:\Users\xieyucheng\AppData\Roaming\Typora\typora-user-images\image-20210205221417030.png)

根据深度可以分为vgg11, vgg13, vgg16, vgg19。

相比于AlexNet，VggNet在卷积的过程中使用了小的卷积核的堆叠的方式。一方面增加了网络的深度，另一方面减少了计算量。

在感受野相同的情况下，采取更小的卷积核进行堆叠能够减少参数量和运算量。

例：一个5*5的卷积核的参数量是25，在进行乘加运算时也进行了25次乘加运算。一个3 *3的卷积核参数量9，乘加运算9次。而2个3 *3卷积核对应的感受野是1个5 *5的卷积核的感受野。

```python
import torch
import torch.nn as nn
import torch.nn.functional as F
import torchvision

class VGGbase(nn.Module):
    def __init__(self, num_classes = 65):
        super(VGGbase, self).__init__()
        # 3 * 224 * 224
        self.conv1 = nn.Sequential(
            nn.Conv2d(in_channels=3, out_channels=64, kernel_size=3, stride=1, padding=1),
            nn.BatchNorm2d(64),
            nn.ReLU()
        )
        self.max_pooling1 = nn.MaxPool2d(kernel_size=2, stride=2)

        # 112 * 112
        self.conv2_1 = nn.Sequential(
            nn.Conv2d(in_channels=64, out_channels=128, kernel_size=3, stride=1, padding=1),
            nn.BatchNorm2d(128),
            nn.ReLU()
        )
        self.conv2_2 = nn.Sequential(
            nn.Conv2d(in_channels=128, out_channels=128, kernel_size=3, stride=1, padding=1),
            nn.BatchNorm2d(128),
            nn.ReLU()
        )
        self.max_pooling2 = nn.MaxPool2d(kernel_size=2, stride=2)


        # 56 * 56
        self.conv3_1 = nn.Sequential(
            nn.Conv2d(in_channels=128, out_channels=256, kernel_size=3, stride=1, padding=1),
            nn.BatchNorm2d(256),
            nn.ReLU()
        )
        self.conv3_2 = nn.Sequential(
            nn.Conv2d(in_channels=256, out_channels=256, kernel_size=3, stride=1, padding=1),
            nn.BatchNorm2d(256),
            nn.ReLU()
        )
        self.max_pooling3 = nn.MaxPool2d(kernel_size=2, stride=2, padding=1)


        # 28 * 28
        self.conv4_1 = nn.Sequential(
            nn.Conv2d(in_channels=256, out_channels=512, kernel_size=3, stride=1, padding=1),
            nn.BatchNorm2d(512),
            nn.ReLU()
        )
        self.conv4_2 = nn.Sequential(
            nn.Conv2d(in_channels=512, out_channels=512, kernel_size=3, stride=1, padding=1),
            nn.BatchNorm2d(512),
            nn.ReLU()
        )
        self.max_pooling4 = nn.MaxPool2d(kernel_size=2, stride=2)

        # 14 * 14

        self.conv5_1 = nn.Sequential(
            nn.Conv2d(in_channels=512, out_channels=512, kernel_size=3, stride=1, padding=1),
            nn.BatchNorm2d(512),
            nn.ReLU()
        )
        self.conv5_2 = nn.Sequential(
            nn.Conv2d(in_channels=512, out_channels=512, kernel_size=3, stride=1, padding=1),
            nn.BatchNorm2d(512),
            nn.ReLU()
        )
        self.max_pooling5 = nn.MaxPool2d(kernel_size=2, stride=2)

        # 7 * 7

        self.classifier = nn.Sequential(
            nn.Linear(in_features = 512 * 7 * 7, out_features = 4096),
            nn.ReLU(),
            nn.Dropout(p = 0.2),
            nn.Linear(in_features = 4096, out_features = 4096),
            nn.ReLU(),
            nn.Dropout(p = 0.2),
            nn.Linear(in_features=4096, out_features = num_classes)

        )
#        self.fc = nn.Linear(512 * 1, num_classes)

    def forward(self, x):
        batchsize = x.size(0)
        out = self.conv1(x)
        out = self.max_pooling1(out)
        out = self.conv2_1(out)
        out = self.conv2_2(out)
        out = self.max_pooling2(out)

        out = self.conv3_1(out)
        out = self.conv3_2(out)
        out = self.max_pooling3(out)

        out = self.conv4_1(out)
        out = self.conv4_2(out)
        out = self.max_pooling4(out)

        out = self.conv5_1(out)
        out = self.conv5_2(out)
        out = self.max_pooling5(out)

        out = out.view(batchsize, -1)
        out = self.classifier(out)
        return out

def VGGNet():
    return VGGbase()
```

上述是vgg13的复现，对于不同深度的VggNet根据上面的结构图在相应位置加入对应的卷积层即可。

VggNet在实际测试中效果不错，对于车牌字符识别这个65分类的任务，不同深度第一个epoch结束后在测试集上的准确率都能达到90％左右。

![image-20210205222940325](C:\Users\xieyucheng\AppData\Roaming\Typora\typora-user-images\image-20210205222940325.png)



## ResNet

ResNet是跳连网络结构的代表，主要的思想是引入跳连的结构来防止梯度消失的问题，进而可以进一步加大网络深度。

在ResNet的基础上有很多扩展的网络结构：ResNeXt、DenseNet、WideResNet、ResNet In ResNet、Inception-ResNet等等。

ResNet论文原文：[Deep Residual Learning for Image Recognition](https://arxiv.org/pdf/1512.03385.pdf)

ResNet结构图

![image-20210205224149482](C:\Users\xieyucheng\AppData\Roaming\Typora\typora-user-images\image-20210205224149482.png)

相比AlexNet和VggNet网络深度明显增加

跳连结构图

![image-20210205224324052](C:\Users\xieyucheng\AppData\Roaming\Typora\typora-user-images\image-20210205224324052.png)

具体实现可以参考这篇文章：[PyTorch实现ResNet亲身实践](https://zhuanlan.zhihu.com/p/263526658)





## 总结

万里长征迈出了第一步。当看到训练终于跑了起来，loss在稳步收敛，正确率不断提高时内心终于感到了喜悦。这一年的理论学习也算是没有白费。

当然这只是第一步，后续还有更多的任务。任重而道远，继续学习。