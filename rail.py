from kivy.clock import Clock
from kivy.lang import Builder
from kivy.utils import get_color_from_hex

from kivymd.app import MDApp
from kivymd.uix.behaviors import RoundedRectangularElevationBehavior
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.button import MDFillRoundFlatIconButton
from kivymd.uix.label import MDLabel
from kivymd.uix.screen import MDScreen

KV = '''
#:import get_color_from_hex kivy.utils.get_color_from_hex
#:import FadeTransition kivy.uix.screenmanager.FadeTransition

#:set rail_bg_color get_color_from_hex("#fffcf4")
#:set fab_button_bg_color get_color_from_hex("#b0f0d6")
#:set selected_item_bg_color get_color_from_hex("#e7e4c0")


<ExtendedButton>
    elevation: 3
    -height: "56dp"


<DrawerClickableItem@MDNavigationDrawerItem>
    focus_color: selected_item_bg_color
    unfocus_color: rail_bg_color


MDScreen:

    MDNavigationLayout:

        ScreenManager:

            MDScreen:

                MDBoxLayout:
                    orientation: "vertical"

                    MDBoxLayout:
                        adaptive_height: True
                        md_bg_color: rail_bg_color
                        padding: "12dp"

                        MDLabel:
                            text: "12:00"
                            adaptive_height: True
                            pos_hint: {"center_y": .5}

                    MDBoxLayout:

                        MDNavigationRail:
                            id: navigation_rail
                            md_bg_color: rail_bg_color
                            selected_color_background: selected_item_bg_color
                            ripple_color_item: selected_item_bg_color
                            on_release: app.switch_screen(*args)

                            MDNavigationRailItem:
                                text: "Python"
                                icon: "language-python"

                            MDNavigationRailItem:
                                text: "JavaScript"
                                icon: "language-javascript"

                            MDNavigationRailItem:
                                text: "CPP"
                                icon: "language-cpp"

                            MDNavigationRailItem:
                                text: "Swift"
                                icon: "language-swift"

                        ScreenManager:
                            id: screen_manager
                            transition:
                                FadeTransition(duration=.2, clearcolor=app.theme_cls.bg_dark)

'''


class ExtendedButton(
    RoundedRectangularElevationBehavior, MDFillRoundFlatIconButton
):
    '''
    Implements a button of type
    `Extended FAB <https://m3.material.io/components/extended-fab/overview>`_.

    .. rubric::
        Extended FABs help people take primary actions.
        They're wider than FABs to accommodate a text label and larger target
        area.

    This type of buttons is not yet implemented in the standard widget set
    of the KivyMD library, so we will implement it ourselves in this class.
    '''

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.padding = "16dp"
        Clock.schedule_once(self.set_spacing)

    def set_spacing(self, interval):
        self.ids.box.spacing = "12dp"

    def set_radius(self, *args):
        if self.rounded_button:
            self._radius = self.radius = self.height / 4


class Example(MDApp):
    def build(self):
        self.theme_cls.material_style = "M3"
        self.theme_cls.primary_palette = "Orange"
        return Builder.load_string(KV)

    def switch_screen(
        self, instance_navigation_rail, instance_navigation_rail_item
    ):
        '''
        Called when tapping on rail menu items. Switches application screens.
        '''

        self.root.ids.screen_manager.current = (
            instance_navigation_rail_item.icon.split("-")[1].lower()
        )

    def on_start(self):
        '''Creates application screens.'''

        navigation_rail_items = self.root.ids.navigation_rail.get_items(self)[:]
        navigation_rail_items.reverse()

        for widget in navigation_rail_items:
            name_screen = widget.icon.split("-")[1].lower()
            screen = MDScreen(
                name=name_screen,
                md_bg_color=get_color_from_hex("#edd769"),
                radius=[18, 0, 0, 0],
            )
            box = MDBoxLayout(padding="12dp")
            label = MDLabel(
                text=name_screen.capitalize(),
                font_style="H1",
                halign="right",
                adaptive_height=True,
                shorten=True,
            )
            box.add_widget(label)
            screen.add_widget(box)
            self.root.ids.screen_manager.add_widget(screen)


Example().run()
