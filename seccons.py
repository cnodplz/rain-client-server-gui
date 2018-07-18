#!/bin/python

import sys
import pygame
from colors import *
from pygame.locals import Color, KEYUP, K_ESCAPE, K_RETURN

class Block(pygame.sprite.Sprite):
    def __init__(self, color=orange_yellow, sp_width=64, sp_height=64):
        super(Block, self).__init__()
        self.image=pygame.Surface((sp_width,sp_height))
        self.image.fill(orange_yellow)
        self.rect=self.image.get_rect()
    def set_position(self, x, y):
        self.rect.x=x
        self.rect.y=y
    def set_image(self, filename=None):
        if (filename!=None):
            self.image=pygame.image.load(filename)
            self.rect=self.image.get_rect()

class Console():
    def __init__(self, concolor=orange_yellow, conmsg="", x_pos=50, y_pos=50):
        self.concolor=concolor
        self.conmsg=conmsg
        self.x_pos=x_pos
        self.y_pos=y_pos
        self.labelcon=confont.render(self.conmsg, 1, (self.concolor))
        self.labellist=[]
        self.labellist.append(self.labelcon)
    def setit(self, concolor, conmsg, x_pos, y_pos):
        self.concolor=concolor
        self.conmsg=conmsg
        self.x_pos=x_pos
        self.y_pos=y_pos
        self.labelcon=confont.render(self.conmsg, 1, (self.concolor))
        self.labellist.append(self.labelcon)
    def setmsg(self, conmsg):
        self.labelcon=confont.render(self.conmsg, 1, (self.concolor))
        self.labellist.append(conmsg)
    def setpos(self, x_pos, y_pos):
        self.x_pos=x_pos
        self.y_pos=y_pos
    def drawit(self):
        tenplus=0
        if len(self.labellist) > 100:
            del self.labellist[0]
        elif len(self.labellist) == 1:
            for y in self.labellist:
                self.labelcon=confont.render(str(y), 1, (self.concolor))
                surface.blit(self.labelcon, (self.x_pos,self.y_pos))
        else:
            for x in self.labellist:
                tenplus+=15
                self.labelcon=confont.render(str(x), 1, (self.concolor))
                surface.blit(self.labelcon, (self.x_pos,self.y_pos + tenplus))

window_size=window_width, window_height=1920,800
surface=pygame.display.set_mode(window_size,pygame.RESIZABLE)
surface.fill(black)
FPS = 60
frames = FPS / 5
'''Sprites/Groups'''
'''block_group=pygame.sprite.Group()
block_group2=pygame.sprite.LayeredUpdates()
b_block=Block()
b_block.set_image("console.gif")
b_block.set_position(0,0)
c_block=Block()
c_block.set_image("console_main.gif")
c_block.set_position(0,0)
block_group2.add(b_block, c_block)'''
pygame.font.init()
confont=pygame.font.Font("/usr/share/fonts/levien-inconsolata/Inconsolata.ttf", 12)
line1=confont.render("aysfef asfs awefaergsregasd  %@#^#&$!", 1, (orange_yellow))

thecon = Console()
# thecon.setit(orange_yellow, "OOOOOOK", 100, 200)
clock = pygame.time.Clock()
n = 0

with open('rain.py-20180623', 'r+') as x:
    for y in x:
        thecon.setmsg(y)

while True:
    for e in pygame.event.get():
        if e.type == KEYUP:
            if e.key == K_ESCAPE:
                sys.exit()
            elif e.key == K_RETURN:
                n += 1
                if n >= len(strips):
                    n = 0
    # surface.blit(image3, (600,400))
    # surface.blit(line1, (50,50))
    thecon.drawit()
    pygame.display.update()
    # block_group2.draw(surface)
    clock.tick(FPS)
