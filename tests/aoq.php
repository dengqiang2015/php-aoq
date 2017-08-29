<?php

error_reporting(E_ALL); 

$aoq = new Aoq();

$aoq->connect('127.0.0.1', 5211);

$aoq->set_read_buffer(16*1024);

$aoq->set_write_buffer(0);

$res = $aoq->status();
var_dump($res);

$res = $aoq->status();
var_dump($res);

$res = $aoq->push('test', 'ok');
var_dump($res);

$res = $aoq->pop('test');
var_dump($res);

$res = $aoq->queues();
var_dump($res);

$res = $aoq->queue('test');
var_dump($res);

$res = $aoq->delqueue('test');
var_dump($res);

$aoq->close();
