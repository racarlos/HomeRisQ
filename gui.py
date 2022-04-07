from kivy.uix.image import Image
from kivy.lang import Builder
from kivymd.app import MDApp
from kivy.core.window import Window



class MainApp(MDApp):

    # Builder Method
    def build(self):
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "BlueGray"
        screen = Builder.load_file('main.kv')
        return screen

    def openRail(self):
        if self.root.ids.rail.rail_state == "open":
            self.root.ids.rail.rail_state = "close"
        else:
            self.root.ids.rail.rail_state = "open"





# Run the App
MainApp().run()