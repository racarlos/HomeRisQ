from kivy.lang import Builder
from kivy.uix.boxlayout import BoxLayout
from kivy.properties import StringProperty
from kivymd.app import MDApp
from kivymd.uix.list import OneLineAvatarIconListItem
from kivymd.uix.dialog import MDDialog

KV = '''
<Item>
    _txt_left_pad: "40dp"

    IconLeftWidget:
        icon: root.icon


<Content>
    orientation: "vertical"
    spacing: "12dp"
    size_hint_y: None
    height: "400dp"

    ScrollView:

        MDList:
            id: Mcontainer

MDFloatLayout:
'''


class Item(OneLineAvatarIconListItem):
    icon = StringProperty()


class Content(BoxLayout):
    pass


class Example(MDApp):
    def on_start(self):
        Mcontent = Content()

        for x in range(0, 7):
            items = Item(text="This is a test", icon="lock")
            Mcontent.ids.Mcontainer.add_widget(items)

        self.MSetFileOptionsdialog = MDDialog(type="custom", content_cls=Mcontent)
        self.MSetFileOptionsdialog.open()

    def build(self):
        return Builder.load_string(KV)


Example().run()