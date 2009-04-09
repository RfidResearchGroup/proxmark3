unsigned char somestring[25];

//*********************************************************************
//********************  SYSTERM HEARTBEAT @ 10 ms *********************
//*********************************************************************
void InitSPI (void)
{
  //set functionalite to pins:
  //port0.11 -> NPCS0
  //port0.12 -> MISO
  //port0.13 -> MOSI
  //port0.14 -> SPCK
  PIOA_PDR = BIT11 | BIT12 | BIT13 | BIT14;
  PIOA_ASR = BIT11 | BIT12 | BIT13 | BIT14;
  PIOA_BSR = 0;


  PMC_PCER |= 1 << 5; // Enable SPI timer clock.

  /****  Fixed mode ****/
  SPI_CR   = 0x81;					//SPI Enable, Sowtware reset
  SPI_CR   = 0x01;					//SPI Enable



  SPI_MR	= 0x000E0011;                           //Master mode
  SPI_CSR0	= 0x01010B11;                           //9 bit

}

//*********************************************************************
//***************************  Task 1  ********************************
//*********************************************************************
void Task_1(void *p)
{
    char beat=0;                                    // just flash the onboard LED for Heatbeat

    while(1)
    {
	if(beat)
	{
            PIOA_SODR = BIT18;
            beat=0;
	}
	else
	{
            PIOA_CODR = BIT18;
            beat=1;
	}

	ctl_timeout_wait(ctl_get_current_time()+ 150);

    }
}
//*********************************************************************
//***************************  Task 2  ********************************
//*********************************************************************
void Task_2(void *p)
{
    unsigned long z;
    unsigned int x,y;
    unsigned char a,b,c,d,e;

    char seconds,minutes,hours;

    unsigned int nowold,tenths;


    InitLCD();


/*******  Put smiley face up in 4096 color mode  *******/
    LCD_Fill(0,0,132,132,Black);

    LCD_Set_Resolution(HIGH_RES);                        // set 4096 color mode

//    ShowImage_4096(0,0,smiley);
    LCD_Set_Resolution(LOW_RES);                        // set 256 color mode

    ctl_timeout_wait(ctl_get_current_time()+ 4000);     // wait 4 seconds to view it

/*******  Do some static on screen  *******/

    LCD_Fill(0,0,132,132,Black);

    for(z=0;z<100000;z++)
    {
        while( (a = rand()) > 132);
        while( (b = rand()) > 132);
        c = rand();
        LCD_PixelPut(a,b,c);
    }

/*******  Do some lines on screen  *******/
    LCD_Fill(0,0,132,132,Black);

    for(z=1;z<300;z++)
    {
        while( (a = rand()) > 132);
        while( (b = rand()) > 132);
        while( (c = rand()) > 132);
        while( (d = rand()) > 132);
        e = rand();                                 // pick color

        LCD_Line(a,b,c,d,e);
    	ctl_timeout_wait(ctl_get_current_time()+ 10);
    }

/*******  Do some Boxes on screen  *******/
    LCD_Fill(0,0,132,132,Black);

    for(z=0;z<300;z++)
    {

        while( (a = rand()) > 132);
        while( (b = rand()) > 132);
        while( (c = rand()) > 132);
        while( (d = rand()) > 132);

        e = rand();                                 // pick color
        LCD_Box(a,b,c,d,e);

        ctl_timeout_wait(ctl_get_current_time()+ 10);
    }
/*******  Do some Circles on screen  *******/
    LCD_Fill(0,0,132,132,Black);

    for(z=0;z<100;z++)
    {

        while( (a = rand()) > 132);
        while( (b = rand()) > 132);
        while( (c = rand()) > 127);                 // diameter

        d = rand();                                 // pick color
        LCD_Circle(a,b,c,d);

        ctl_timeout_wait(ctl_get_current_time()+ 10);
    }

/*******  Do some Thick Circles on screen  *******/
    LCD_Fill(0,0,132,132,Black);

    for(z=0;z<25;z++)
    {
        while( (a = rand()) > 132);
        while( (b = rand()) > 132);
        while( (c = rand()) > 40);                 // diameter
        while( (d = rand()) > 10);                 // wall thicknes
        e = rand();                                 // pick color
        LCD_Thick_Circle(a,b,c,d,e);

        ctl_timeout_wait(ctl_get_current_time()+ 1);
    }

/*******  Do something funky to wipe screen  *******/
	b=0;

	for(a=0;a<131;a++)
	{
            LCD_Line(a,b,65,65,0x62);
	}
	for(b=0;b<131;b++)
	{
            LCD_Line(a,b,65,65,0x62);
	}
	for(;a>1;a--)
	{
            LCD_Line(a,b,65,65,0x62);
	}
	for(;b>1;b--)
	{
            LCD_Line(a,b,65,65,0x62);
	}

	ctl_timeout_wait(ctl_get_current_time()+ 1000);

/*******  Show Image scrolling *******/
    LCD_Fill(0,0,132,132,Black);

    ShowImage(0,50,sparkfun);

    sprintf(somestring,"Thanks SparkFun");
    LCD_String(somestring,&FONT8x8F[0][0],5,10,LightGreen,Black);

    ctl_timeout_wait(ctl_get_current_time()+ 2000);     // hold sparkfun image for a bit

    for(y=50;y<140;y++)
    {
        LCD_Line(0,y-1,132,y-1,Black);                  // wipe the white line as it moves down
	ShowImage(0,y,sparkfun);                        // move image to Y location
	ctl_timeout_wait(ctl_get_current_time()+ 25);   // wait a bit
    }

/*******  Run radar in loop with example fonts displayed  *******/
    LCD_Fill(0,0,132,132,Black);

    LCD_Thick_Circle(66,66,30,2,DarkBlue);

    y=0;

    while (1)
    {
	LCD_Circle_Line(66,66,28,0,y,LightGreen);

	ctl_timeout_wait(ctl_get_current_time()+ 1);

	tenths = ctl_current_time / 1000;

	if(tenths != nowold)
	{
            nowold = tenths;

            if(++seconds == 60)
            {
                seconds = 0;

                if(++minutes == 60)
                {
                    minutes=0;
                    hours++;
		}
            }
	}


	printf("a=%6lu - b=%6lu - c=%6lu - d=%6lu  :  Time=%lu\r\n",a,b,c,d,ctl_current_time);

	sprintf(somestring,"%05lu",y);
	LCD_String(somestring,&FONT6x8[0][0],52,25,White,Black);

	sprintf(somestring,"Time:%02u:%02u:%02u",hours,minutes,seconds);
	LCD_String(somestring,&FONT8x8F[0][0],14,10,DarkRed,Black);

	sprintf(somestring,"Time:%02u:%02u:%02u",hours,minutes,seconds);
	LCD_String(somestring,&FONT8x16[0][0],14,115,LightGreen,Black);

	LCD_Circle_Line(66,66,28,0,y,Black);

        if(++y==360)
        {
            y=0;
        }

	ctl_timeout_wait(ctl_get_current_time()+ 10);

    }
}

/*************************************************************************
 *********************        Main Module        *************************
 *********************                           *************************
 *********************     Initialize Program    *************************
 *********************         Sequences         *************************
 *********************                           *************************
 *************************************************************************/
int main(void)
{
	BoardInit();

	InitSPI();

	while (1)
	{
            Idle();
	}

	return 0;
}
