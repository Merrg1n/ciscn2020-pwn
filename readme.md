# 赛题设计说明

### 题目信息：

* 题目名称：new_fc
* 预估难度：中等偏难     （简单/中等偏易/中等偏难/困难）

### 题目描述：
Ubuntu 18.04


### 题目考点(至少2点)
1. 虚拟机
2. Use after free
3. TCache Attack


### 思路简述
利用虚拟机的 load 指令 leak 出 libc 地址，然后使用虚拟机的 save 指令修改 chunk，利用 tcache attack 修改 free_hook 为 system getshell。